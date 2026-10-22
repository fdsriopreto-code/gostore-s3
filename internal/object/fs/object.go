package fs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lojadopocket/gostore/internal/object"
)

func (f *FS) ensureBucket(bucket string) error {
	if !validBucketName(bucket) {
		return object.ErrBucketNameInvalid
	}
	st, err := os.Stat(f.bucketDir(bucket))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return object.BucketNotFound{Bucket: bucket}
		}
		return err
	}
	if !st.IsDir() {
		return object.BucketNotFound{Bucket: bucket}
	}
	return nil
}

// PutObject stores a full object in one request.
func (f *FS) PutObject(ctx context.Context, bucket, obj string, data *object.PutObjReader, opts object.ObjectOptions) (object.ObjectInfo, error) {
	if opts.Versioned || opts.VersionSuspended {
		return f.putVersion(ctx, bucket, obj, data, opts)
	}
	if err := f.ensureBucket(bucket); err != nil {
		return object.ObjectInfo{}, err
	}
	if !validObjectName(obj) {
		return object.ObjectInfo{}, object.ErrObjectNameInvalid
	}

	lk := f.NewNSLock(bucket, obj)
	ctx2, _ := lk.GetLock(context.Background(), 0)
	defer lk.Unlock(ctx2)

	if opts.CheckPrecondFn != nil {
		cur, _ := f.getInfoUnlocked(bucket, obj)
		if opts.CheckPrecondFn(cur) {
			return object.ObjectInfo{}, object.ErrPreconditionFailed
		}
	}

	dataPath := f.objDataPath(bucket, obj)
	if err := f.checkPathConflicts(bucket, obj); err != nil {
		return object.ObjectInfo{}, err
	}

	var tmp, md5hex string
	var n int64
	var sseMeta objMeta
	var err error
	encrypt := f.sseRequested(opts)
	ssec := len(opts.SSECustomerKey) == 32
	if ssec {
		tmp, n, md5hex, sseMeta, err = f.encryptToTmpSSEC(data, data.Size(), opts.SSECustomerKey, opts.SSECustomerKeyMD5)
	} else if encrypt {
		tmp, n, md5hex, sseMeta, err = f.encryptToTmp(data, data.Size())
	} else {
		tmp, n, md5hex, err = f.copyToTmpAndHash(data, data.Size())
	}
	if err != nil {
		return object.ObjectInfo{}, err
	}
	defer os.Remove(tmp)

	if err := os.MkdirAll(filepath.Dir(dataPath), 0o755); err != nil {
		return object.ObjectInfo{}, err
	}
	if err := os.Rename(tmp, dataPath); err != nil {
		return object.ObjectInfo{}, err
	}

	now := time.Now().UTC()
	if !opts.MTime.IsZero() {
		now = opts.MTime.UTC()
	}
	m := objMeta{
		Size: n, ModTime: now, ETag: md5hex,
		ContentType: opts.UserDefined["content-type"],
		ContentEnc:  opts.UserDefined["content-encoding"],
		UserMeta:    stripReserved(opts.UserDefined),
		UserTags:    opts.UserTags,
	}
	if ssec || encrypt {
		st, _ := os.Stat(dataPath)
		m.Size = st.Size()
		m.SSE = sseMeta.SSE
		m.PlainSize = sseMeta.PlainSize
		m.EncDEK = sseMeta.EncDEK
		m.NoncePrefix = sseMeta.NoncePrefix
		m.SSECKeyMD5 = sseMeta.SSECKeyMD5
	}
	if err := writeMetaFile(f.objMetaPath(bucket, obj), m); err != nil {
		return object.ObjectInfo{}, err
	}
	return m.toObjectInfo(bucket, obj), nil
}

// checkPathConflicts rejects a key when an ancestor path element is an
// existing file, or the key itself is an existing directory.
func (f *FS) checkPathConflicts(bucket, obj string) error {
	if st, err := os.Stat(f.objDataPath(bucket, obj)); err == nil && st.IsDir() {
		return object.ErrObjectExistsAsDir
	}
	parts := strings.Split(obj, "/")
	cur := f.bucketDir(bucket)
	for _, p := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, p)
		if st, err := os.Stat(cur); err == nil && !st.IsDir() {
			return object.ErrObjectExistsAsDir
		}
	}
	return nil
}

func stripReserved(md map[string]string) map[string]string {
	if md == nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range md {
		lk := strings.ToLower(k)
		switch lk {
		case "content-type", "content-encoding", "etag":
			continue
		}
		if strings.HasPrefix(lk, "x-amz-") && !strings.HasPrefix(lk, "x-amz-meta-") {
			continue
		}
		out[strings.TrimPrefix(lk, "x-amz-meta-")] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (f *FS) getInfoUnlocked(bucket, obj string) (object.ObjectInfo, error) {
	dataPath := f.objDataPath(bucket, obj)
	st, err := os.Stat(dataPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return object.ObjectInfo{}, object.ObjectNotFound{Bucket: bucket, Object: obj}
		}
		return object.ObjectInfo{}, err
	}
	if st.IsDir() {
		return object.ObjectInfo{}, object.ObjectNotFound{Bucket: bucket, Object: obj}
	}
	m, err := readMetaFile(f.objMetaPath(bucket, obj))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return object.ObjectInfo{}, err
		}
		// Externally-placed file: synthesize metadata (real md5).
		md5hex, herr := md5File(dataPath)
		if herr != nil {
			return object.ObjectInfo{}, herr
		}
		m = objMeta{Size: st.Size(), ModTime: st.ModTime().UTC(), ETag: md5hex}
	}
	return m.toObjectInfo(bucket, obj), nil
}

func (f *FS) GetObjectInfo(_ context.Context, bucket, obj string, opts object.ObjectOptions) (object.ObjectInfo, error) {
	if err := f.ensureBucket(bucket); err != nil {
		return object.ObjectInfo{}, err
	}
	lk := f.NewNSLock(bucket, obj)
	ctx2, _ := lk.GetRLock(context.Background(), 0)
	defer lk.RUnlock(ctx2)
	if opts.Versioned || opts.VersionSuspended || opts.VersionID != "" {
		oi, _, err := f.getVersionInfo(bucket, obj, opts.VersionID)
		if err == nil || !errors.Is(err, object.ErrObjectNotFound) {
			return oi, err
		}
		// fall through to plain lookup for un-migrated keys
	}
	return f.getInfoUnlocked(bucket, obj)
}

func (f *FS) GetObjectNInfo(_ context.Context, bucket, obj string, rs *object.HTTPRangeSpec, _ http.Header, opts object.ObjectOptions) (*object.GetObjectReader, error) {
	if err := f.ensureBucket(bucket); err != nil {
		return nil, err
	}
	lk := f.NewNSLock(bucket, obj)
	ctx2, _ := lk.GetRLock(context.Background(), 0)

	var oi object.ObjectInfo
	var ent verEntry
	var err error
	versioned := opts.Versioned || opts.VersionSuspended || opts.VersionID != ""
	if versioned {
		oi, ent, err = f.getVersionInfo(bucket, obj, opts.VersionID)
		if errors.Is(err, object.ErrObjectNotFound) {
			oi, err = f.getInfoUnlocked(bucket, obj) // un-migrated key
			versioned = false
		}
	} else {
		oi, err = f.getInfoUnlocked(bucket, obj)
	}
	if err != nil {
		lk.RUnlock(ctx2)
		return nil, err
	}
	if opts.CheckPrecondFn != nil && opts.CheckPrecondFn(oi) {
		lk.RUnlock(ctx2)
		return nil, object.ErrPreconditionFailed
	}

	// Encrypted object (non-versioned path): decrypt transparently.
	if !versioned {
		if m, merr := readMetaFile(f.objMetaPath(bucket, obj)); merr == nil && m.SSE != "" {
			var start, length int64 = 0, oi.Size
			if rs != nil {
				start, length, err = resolveRange(rs, oi.Size)
				if err != nil {
					lk.RUnlock(ctx2)
					return nil, err
				}
				oi.Size = length
			}
			var rc io.ReadCloser
			var derr error
			if m.SSE == "SSE-C" {
				if len(opts.SSECustomerKey) != 32 {
					lk.RUnlock(ctx2)
					return nil, object.ErrSSECKeyRequired
				}
				if opts.SSECustomerKeyMD5 != m.SSECKeyMD5 {
					lk.RUnlock(ctx2)
					return nil, object.ErrSSECKeyMismatch
				}
				rc, derr = f.openDecryptingSSEC(f.objDataPath(bucket, obj), m, opts.SSECustomerKey, start, length)
			} else {
				rc, derr = f.openDecrypting(f.objDataPath(bucket, obj), m, start, length)
			}
			if derr != nil {
				lk.RUnlock(ctx2)
				return nil, derr
			}
			return &object.GetObjectReader{
				ObjInfo:    oi,
				ReadCloser: &decCloserUnlock{r: rc, onClose: func() { lk.RUnlock(ctx2) }},
			}, nil
		}
	}

	var fh *os.File
	if versioned {
		fh, err = f.openVersionData(bucket, obj, opts.VersionID, ent)
	} else {
		fh, err = os.Open(f.objDataPath(bucket, obj))
	}
	if err != nil {
		lk.RUnlock(ctx2)
		return nil, err
	}

	var start, length int64 = 0, oi.Size
	if rs != nil {
		start, length, err = resolveRange(rs, oi.Size)
		if err != nil {
			_ = fh.Close()
			lk.RUnlock(ctx2)
			return nil, err
		}
		if _, err := fh.Seek(start, io.SeekStart); err != nil {
			_ = fh.Close()
			lk.RUnlock(ctx2)
			return nil, err
		}
		oi.Size = length
	}

	rc := &fileReader{
		f:       fh,
		remain:  length,
		onClose: func() { lk.RUnlock(ctx2) },
	}
	return &object.GetObjectReader{ObjInfo: oi, ReadCloser: rc}, nil
}

// resolveRange turns an HTTPRangeSpec into (start, length), validating it
// against the object size.
func resolveRange(rs *object.HTTPRangeSpec, size int64) (start, length int64, err error) {
	if rs.IsSuffixLength {
		n := -rs.Start
		if n <= 0 {
			return 0, 0, object.ErrInvalidRange
		}
		if n > size {
			n = size
		}
		return size - n, n, nil
	}
	if rs.Start < 0 || rs.Start >= size {
		return 0, 0, object.ErrInvalidRange
	}
	end := rs.End
	if end < 0 || end >= size {
		end = size - 1
	}
	if end < rs.Start {
		return 0, 0, object.ErrInvalidRange
	}
	return rs.Start, end - rs.Start + 1, nil
}

type fileReader struct {
	f       *os.File
	remain  int64
	onClose func()
}

func (r *fileReader) Read(p []byte) (int, error) {
	if r.remain <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remain {
		p = p[:r.remain]
	}
	n, err := r.f.Read(p)
	r.remain -= int64(n)
	return n, err
}

func (r *fileReader) Close() error {
	err := r.f.Close()
	if r.onClose != nil {
		r.onClose()
	}
	return err
}

func (f *FS) DeleteObject(ctx context.Context, bucket, obj string, opts object.ObjectOptions) (object.ObjectInfo, error) {
	if err := f.ensureBucket(bucket); err != nil {
		return object.ObjectInfo{}, err
	}
	if !validObjectName(obj) {
		return object.ObjectInfo{}, object.ErrObjectNameInvalid
	}
	if opts.Versioned || opts.VersionSuspended || opts.VersionID != "" {
		return f.deleteVersion(ctx, bucket, obj, opts.VersionID, opts.VersionSuspended, opts.BypassGovernance)
	}
	lk := f.NewNSLock(bucket, obj)
	ctx2, _ := lk.GetLock(context.Background(), 0)
	defer lk.Unlock(ctx2)

	dataPath := f.objDataPath(bucket, obj)
	_ = os.Remove(dataPath)
	_ = os.Remove(f.objMetaPath(bucket, obj))
	f.pruneEmptyDirs(filepath.Dir(dataPath), f.bucketDir(bucket))
	f.pruneEmptyDirs(filepath.Dir(f.objMetaPath(bucket, obj)), f.metaBucketDir(bucket))
	return object.ObjectInfo{Bucket: bucket, Name: obj}, nil
}

func (f *FS) DeleteObjects(ctx context.Context, bucket string, objs []object.ObjectToDelete, opts object.ObjectOptions) ([]object.DeletedObject, []error) {
	deleted := make([]object.DeletedObject, len(objs))
	errs := make([]error, len(objs))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, o := range objs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := f.DeleteObject(ctx, bucket, name, opts); err != nil {
				errs[i] = err
				return
			}
			deleted[i] = object.DeletedObject{ObjectName: name}
		}(i, o.ObjectName)
	}
	wg.Wait()
	return deleted, errs
}

// pruneEmptyDirs removes empty directories from leaf up to (not including) stop.
func (f *FS) pruneEmptyDirs(leaf, stop string) {
	for leaf != stop && len(leaf) > len(stop) {
		if err := os.Remove(leaf); err != nil {
			return // non-empty or gone
		}
		leaf = filepath.Dir(leaf)
	}
}

func (f *FS) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, srcInfo object.ObjectInfo, srcOpts, dstOpts object.ObjectOptions) (object.ObjectInfo, error) {
	if err := f.ensureBucket(srcBucket); err != nil {
		return object.ObjectInfo{}, err
	}
	if err := f.ensureBucket(dstBucket); err != nil {
		return object.ObjectInfo{}, err
	}
	// Version-aware copy (a specific source version, or a copy that must land
	// as a new version): read the source fully, release its read lock, then
	// write — for a same-object restore the reader's RLock would otherwise
	// deadlock PutObject's write lock.
	if srcOpts.VersionID != "" || dstOpts.Versioned || dstOpts.VersionSuspended {
		gr, gerr := f.GetObjectNInfo(ctx, srcBucket, srcObject, nil, nil, object.ObjectOptions{VersionID: srcOpts.VersionID})
		if gerr != nil {
			return object.ObjectInfo{}, gerr
		}
		buf, rerr := io.ReadAll(gr)
		ud := map[string]string{}
		for k, v := range gr.ObjInfo.UserDefined {
			ud[k] = v
		}
		_ = gr.Close()
		if rerr != nil {
			return object.ObjectInfo{}, rerr
		}
		return f.PutObject(ctx, dstBucket, dstObject,
			object.NewPutObjReader(bytes.NewReader(buf), int64(len(buf)), int64(len(buf))),
			object.ObjectOptions{UserDefined: ud, UserTags: dstOpts.UserTags,
				Versioned: dstOpts.Versioned, VersionSuspended: dstOpts.VersionSuspended})
	}

	src, err := f.getInfoUnlocked(srcBucket, srcObject)
	if err != nil {
		return object.ObjectInfo{}, err
	}

	sameObject := srcBucket == dstBucket && srcObject == dstObject
	replace := strings.EqualFold(dstOpts.UserDefined["x-amz-metadata-directive"], "REPLACE") ||
		dstOpts.UserDefined["_directive"] == "REPLACE"

	if sameObject && !replace {
		// No-op copy onto itself with COPY directive: just refresh mtime.
		return src, nil
	}

	if sameObject && replace {
		m, err := readMetaFile(f.objMetaPath(srcBucket, srcObject))
		if err != nil {
			return object.ObjectInfo{}, err
		}
		m.ModTime = time.Now().UTC()
		m.ContentType = dstOpts.UserDefined["content-type"]
		m.ContentEnc = dstOpts.UserDefined["content-encoding"]
		m.UserMeta = stripReserved(dstOpts.UserDefined)
		if dstOpts.UserTags != "" {
			m.UserTags = dstOpts.UserTags
		}
		if err := writeMetaFile(f.objMetaPath(srcBucket, srcObject), m); err != nil {
			return object.ObjectInfo{}, err
		}
		return m.toObjectInfo(dstBucket, dstObject), nil
	}

	// Cross-object copy: stream data through PutObject.
	rc, err := os.Open(f.objDataPath(srcBucket, srcObject))
	if err != nil {
		return object.ObjectInfo{}, err
	}
	defer rc.Close()

	ud := map[string]string{}
	if replace {
		for k, v := range dstOpts.UserDefined {
			ud[k] = v
		}
	} else {
		for k, v := range src.UserDefined {
			ud[k] = v
		}
	}
	pr := object.NewPutObjReader(rc, src.Size, src.Size)
	return f.PutObject(ctx, dstBucket, dstObject, pr, object.ObjectOptions{UserDefined: ud, UserTags: dstOpts.UserTags})
}
