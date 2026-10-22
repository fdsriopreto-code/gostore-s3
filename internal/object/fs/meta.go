package fs

import (
	"encoding/json"
	"os"
	"time"

	"github.com/lojadopocket/gostore/internal/object"
)

// objMeta is the on-disk metadata sidecar for one object. Stored as JSON in
// M1 (msgpack + the xl.meta directory layout arrive with erasure coding in
// M4). It is the source of truth for everything the data file itself cannot
// carry: ETag, content-type, user metadata, multipart part list.
type objMeta struct {
	Version     int               `json:"v"`
	Size        int64             `json:"size"`
	ModTime     time.Time         `json:"modTime"`
	ETag        string            `json:"etag"`
	ContentType string            `json:"contentType,omitempty"`
	ContentEnc  string            `json:"contentEncoding,omitempty"`
	UserMeta    map[string]string `json:"userMeta,omitempty"` // without x-amz-meta- prefix
	UserTags    string            `json:"userTags,omitempty"`
	Parts       []objMetaPart     `json:"parts,omitempty"` // set for multipart objects

	// SSE-S3 at rest (M11). When SSE == "AES256": Size is the ciphertext size
	// on disk, PlainSize the logical object size, ETag the plaintext md5.
	SSE         string `json:"sse,omitempty"`
	PlainSize   int64  `json:"plainSize,omitempty"`
	EncDEK      string `json:"encDEK,omitempty"`      // hex, master-key-wrapped data key
	NoncePrefix string `json:"noncePrefix,omitempty"` // hex, 4 bytes

	// SSE-C: when SSE == "SSE-C" the data key is the customer-provided key
	// (never stored); SSECKeyMD5 is its base64 MD5, used to reject a read
	// presenting the wrong key. EncDEK is empty for SSE-C.
	SSECKeyMD5 string `json:"sseCKeyMD5,omitempty"`
}

type objMetaPart struct {
	Number     int    `json:"n"`
	Size       int64  `json:"size"`
	ActualSize int64  `json:"actualSize"`
	ETag       string `json:"etag"`
}

func (m objMeta) toObjectInfo(bucket, name string) object.ObjectInfo {
	size := m.Size
	if m.SSE != "" {
		size = m.PlainSize
	}
	oi := object.ObjectInfo{
		Bucket:          bucket,
		Name:            name,
		Size:            size,
		ModTime:         m.ModTime,
		ETag:            m.ETag,
		ContentType:     m.ContentType,
		ContentEncoding: m.ContentEnc,
		UserDefined:     map[string]string{},
		UserTags:        m.UserTags,
		StorageClass:    "STANDARD",
		IsLatest:        true,
	}
	for k, v := range m.UserMeta {
		oi.UserDefined[k] = v
	}
	if m.ContentType != "" {
		oi.UserDefined["content-type"] = m.ContentType
	}
	if m.SSE == "SSE-C" {
		oi.UserDefined["x-amz-server-side-encryption-customer-algorithm"] = "AES256"
		if m.SSECKeyMD5 != "" {
			oi.UserDefined["x-amz-server-side-encryption-customer-key-md5"] = m.SSECKeyMD5
		}
	} else if m.SSE != "" {
		oi.UserDefined["x-amz-server-side-encryption"] = m.SSE
	}
	for _, p := range m.Parts {
		oi.Parts = append(oi.Parts, object.ObjectPartInfo{
			Number: p.Number, Size: p.Size, ActualSize: p.ActualSize, ETag: p.ETag,
		})
	}
	return oi
}

func writeMetaFile(path string, m objMeta) error {
	m.Version = 1
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o644)
}

func readMetaFile(path string) (objMeta, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return objMeta{}, err
	}
	var m objMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return objMeta{}, err
	}
	return m, nil
}
