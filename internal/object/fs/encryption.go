package fs

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"

	"github.com/lojadopocket/gostore/internal/object"
	"github.com/lojadopocket/gostore/internal/sse"
)

// sseRequested reports whether the request asked for (or the object already
// uses) SSE-S3 and the backend can do it.
func (f *FS) sseRequested(opts object.ObjectOptions) bool {
	if f.kms == nil {
		return false
	}
	v := opts.UserDefined["x-amz-server-side-encryption"]
	return v == "AES256" || v == sse.Algorithm
}

// encryptToTmp reads plaintext from r, writes the sealed chunk stream to a
// fresh tmp file, and returns the tmp path, plaintext size, plaintext md5
// hex, and the metadata fields to persist.
func (f *FS) encryptToTmp(r io.Reader, expected int64) (tmp string, plainSize int64, md5hex string, m objMeta, err error) {
	dek, err := f.kms.GenerateDataKey()
	if err != nil {
		return "", 0, "", objMeta{}, err
	}
	prefix, err := sse.NewNoncePrefix()
	if err != nil {
		return "", 0, "", objMeta{}, err
	}
	wrapped, err := f.kms.WrapKey(dek)
	if err != nil {
		return "", 0, "", objMeta{}, err
	}

	tmp = f.tmpPath()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", 0, "", objMeta{}, err
	}
	h := md5.New()
	counted := &countReader{r: io.TeeReader(r, h)}
	if _, err = io.Copy(out, sse.EncryptReader(counted, dek, prefix)); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", 0, "", objMeta{}, err
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", 0, "", objMeta{}, err
	}
	if err = out.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", 0, "", objMeta{}, err
	}
	if expected >= 0 && counted.n != expected {
		_ = os.Remove(tmp)
		return "", 0, "", objMeta{}, object.ErrIncompleteBody
	}
	m = objMeta{
		SSE:         sse.Algorithm,
		PlainSize:   counted.n,
		EncDEK:      hex.EncodeToString(wrapped),
		NoncePrefix: hex.EncodeToString(prefix),
	}
	return tmp, counted.n, hex.EncodeToString(h.Sum(nil)), m, nil
}

// encryptToTmpSSEC encrypts r with a customer-provided key (SSE-C): the key is
// used directly as the data key and never stored — only its MD5, to validate
// the key on read.
func (f *FS) encryptToTmpSSEC(r io.Reader, expected int64, key []byte, keyMD5 string) (tmp string, plainSize int64, md5hex string, m objMeta, err error) {
	prefix, err := sse.NewNoncePrefix()
	if err != nil {
		return "", 0, "", objMeta{}, err
	}
	tmp = f.tmpPath()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", 0, "", objMeta{}, err
	}
	h := md5.New()
	counted := &countReader{r: io.TeeReader(r, h)}
	if _, err = io.Copy(out, sse.EncryptReader(counted, key, prefix)); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return "", 0, "", objMeta{}, err
	}
	if err = out.Sync(); err == nil {
		err = out.Close()
	} else {
		_ = out.Close()
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", 0, "", objMeta{}, err
	}
	if expected >= 0 && counted.n != expected {
		_ = os.Remove(tmp)
		return "", 0, "", objMeta{}, object.ErrIncompleteBody
	}
	m = objMeta{
		SSE:         "SSE-C",
		PlainSize:   counted.n,
		NoncePrefix: hex.EncodeToString(prefix),
		SSECKeyMD5:  keyMD5,
	}
	return tmp, counted.n, hex.EncodeToString(h.Sum(nil)), m, nil
}

// openDecryptingSSEC decrypts an SSE-C object [off, off+length) with the
// customer-provided key.
func (f *FS) openDecryptingSSEC(path string, m objMeta, key []byte, off, length int64) (io.ReadCloser, error) {
	prefix, err := hex.DecodeString(m.NoncePrefix)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if off < 0 {
		off = 0
	}
	if length < 0 || off+length > m.PlainSize {
		length = m.PlainSize - off
	}
	firstChunk, cipherOff, intraSkip := sse.CipherOffsetForPlain(off)
	if cipherOff > 0 {
		if _, err := fh.Seek(cipherOff, io.SeekStart); err != nil {
			_ = fh.Close()
			return nil, err
		}
	}
	dr := sse.DecryptRange(fh, key, prefix, firstChunk, intraSkip, length)
	return &decCloser{r: dr, c: fh}, nil
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	c.n += int64(k)
	return k, err
}

// openDecrypting returns a reader over plaintext bytes [off, off+length) of an
// encrypted object stored at path.
func (f *FS) openDecrypting(path string, m objMeta, off, length int64) (io.ReadCloser, error) {
	wrapped, err := hex.DecodeString(m.EncDEK)
	if err != nil {
		return nil, err
	}
	dek, err := f.kms.UnwrapKey(wrapped)
	if err != nil {
		return nil, err
	}
	prefix, err := hex.DecodeString(m.NoncePrefix)
	if err != nil {
		return nil, err
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if off < 0 {
		off = 0
	}
	if length < 0 || off+length > m.PlainSize {
		length = m.PlainSize - off
	}
	firstChunk, cipherOff, intraSkip := sse.CipherOffsetForPlain(off)
	if cipherOff > 0 {
		if _, err := fh.Seek(cipherOff, io.SeekStart); err != nil {
			_ = fh.Close()
			return nil, err
		}
	}
	dr := sse.DecryptRange(fh, dek, prefix, firstChunk, intraSkip, length)
	return &decCloser{r: dr, c: fh}, nil
}

type decCloser struct {
	r io.Reader
	c io.Closer
}

func (d *decCloser) Read(p []byte) (int, error) { return d.r.Read(p) }
func (d *decCloser) Close() error               { return d.c.Close() }

// decCloserUnlock wraps a decrypting reader and releases the namespace lock
// on Close.
type decCloserUnlock struct {
	r       io.ReadCloser
	onClose func()
}

func (d *decCloserUnlock) Read(p []byte) (int, error) { return d.r.Read(p) }
func (d *decCloserUnlock) Close() error {
	err := d.r.Close()
	if d.onClose != nil {
		d.onClose()
	}
	return err
}
