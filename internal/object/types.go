package object

import (
	"io"
	"time"
)

// ---------------------------------------------------------------------------
// Bucket
// ---------------------------------------------------------------------------

// BucketInfo describes a bucket.
type BucketInfo struct {
	Name    string
	Created time.Time

	// Set once the corresponding features land (M10).
	Versioning    bool
	ObjectLocking bool
}

// MakeBucketOptions carries options for MakeBucket.
type MakeBucketOptions struct {
	Location          string
	LockEnabled       bool
	VersioningEnabled bool
	// ForceCreate skips the "already exists" check (used by internal healing).
	ForceCreate bool
}

// DeleteBucketOptions carries options for DeleteBucket.
type DeleteBucketOptions struct {
	// Force deletes a non-empty bucket (admin/internal only).
	Force bool
	// SkipObjectDeletion, when Force is set, removes bucket metadata without
	// walking objects (used during teardown).
	SkipObjectDeletion bool
}

// ---------------------------------------------------------------------------
// Object
// ---------------------------------------------------------------------------

// ObjectInfo is the canonical metadata for a stored object (or a specific
// version of one).
type ObjectInfo struct {
	Bucket string
	Name   string

	Size            int64
	IsDir           bool
	ModTime         time.Time
	ETag            string
	ContentType     string
	ContentEncoding string

	// Versioning (M10).
	VersionID    string
	IsLatest     bool
	DeleteMarker bool

	// StorageClass, e.g. "STANDARD" or "REDUCED_REDUNDANCY".
	StorageClass string

	// UserDefined holds x-amz-meta-* headers and internal reserved keys
	// (content-type, etag, sse fields, ...). Keys are canonicalized lower-case
	// without the "x-amz-meta-" prefix for user metadata.
	UserDefined map[string]string

	// UserTags is the raw "k1=v1&k2=v2" tag set (M10).
	UserTags string

	// Parts is populated for multipart objects (ordered by PartNumber).
	Parts []ObjectPartInfo

	// Expires is the HTTP Expires header value, if set.
	Expires time.Time

	// Inlined reports the object data was stored inline with metadata
	// (small-object optimization in the erasure backend, M4).
	Inlined bool
}

// ObjectPartInfo describes one part of a multipart object as persisted.
type ObjectPartInfo struct {
	Number     int
	Size       int64 // decrypted/plain size
	ActualSize int64 // size on disk (may differ with compression/SSE)
	ETag       string
	ModTime    time.Time
}

// ObjectOptions carries per-call options threaded through the whole stack.
// Mirrors MinIO's ObjectOptions grab-bag.
type ObjectOptions struct {
	VersionID string
	MTime     time.Time

	UserDefined map[string]string // metadata to persist (PUT/COPY)
	UserTags    string

	// Compress asks the backend to store the object zstd-compressed at rest
	// (set from the bucket's compression config; backend may still skip it
	// for already-compressed content-types / tiny objects).
	Compress bool

	// Conditional request predicates (M3).
	CheckPrecondFn func(ObjectInfo) bool

	// DeletePrefix removes every object under the given prefix (internal).
	DeletePrefix bool

	// Versioned / VersionSuspended reflect bucket versioning state at call time.
	Versioned        bool
	VersionSuspended bool

	// Object Lock (WORM). LockMode is "GOVERNANCE" | "COMPLIANCE" | "".
	LockMode         string
	LockRetainUntil  time.Time
	LockLegalHold    string // "ON" | "OFF" | ""
	BypassGovernance bool   // s3:BypassGovernanceRetention + explicit header

	// Server-side encryption context (M11) — opaque for now.
	ServerSideEncryption any

	// SSE-C: a customer-provided 32-byte key for this request only. The
	// server encrypts/decrypts with it and never stores it — only its MD5,
	// to validate the key presented on read. Non-nil selects SSE-C.
	SSECustomerKey    []byte
	SSECustomerKeyMD5 string

	// PartNumber, when non-zero, requests a single part of a multipart object.
	PartNumber int
}

// ObjectToDelete identifies one object (optionally a version) for DeleteObjects.
type ObjectToDelete struct {
	ObjectName string
	VersionID  string
}

// DeletedObject is the result entry for a successful delete in DeleteObjects.
type DeletedObject struct {
	ObjectName            string
	VersionID             string
	DeleteMarker          bool
	DeleteMarkerVersionID string
}

// CompletePart is a client-supplied part reference in CompleteMultipartUpload.
type CompletePart struct {
	PartNumber int
	ETag       string
}

// ---------------------------------------------------------------------------
// Listing results
// ---------------------------------------------------------------------------

// ListObjectsInfo is the result of the v1 list operation.
type ListObjectsInfo struct {
	IsTruncated bool
	NextMarker  string
	Objects     []ObjectInfo
	Prefixes    []string // common prefixes (from delimiter)
}

// ListObjectsV2Info is the result of the v2 list operation.
type ListObjectsV2Info struct {
	IsTruncated           bool
	ContinuationToken     string
	NextContinuationToken string
	Objects               []ObjectInfo
	Prefixes              []string
}

// ListObjectVersionsInfo is the result of listing object versions (M10).
type ListObjectVersionsInfo struct {
	IsTruncated         bool
	NextMarker          string
	NextVersionIDMarker string
	Objects             []ObjectInfo
	Prefixes            []string
}

// ---------------------------------------------------------------------------
// Multipart
// ---------------------------------------------------------------------------

// NewMultipartUploadResult is returned by NewMultipartUpload.
type NewMultipartUploadResult struct {
	UploadID string
}

// MultipartInfo describes an in-progress multipart upload.
type MultipartInfo struct {
	Bucket      string
	Object      string
	UploadID    string
	Initiated   time.Time
	UserDefined map[string]string
}

// PartInfo is the result of PutObjectPart / an entry of ListObjectParts.
type PartInfo struct {
	PartNumber   int
	LastModified time.Time
	ETag         string
	Size         int64
	ActualSize   int64
}

// ListPartsInfo is the result of ListObjectParts.
type ListPartsInfo struct {
	Bucket               string
	Object               string
	UploadID             string
	PartNumberMarker     int
	NextPartNumberMarker int
	MaxParts             int
	IsTruncated          bool
	Parts                []PartInfo
	UserDefined          map[string]string
}

// ListMultipartsInfo is the result of ListMultipartUploads.
type ListMultipartsInfo struct {
	KeyMarker          string
	UploadIDMarker     string
	NextKeyMarker      string
	NextUploadIDMarker string
	MaxUploads         int
	IsTruncated        bool
	Uploads            []MultipartInfo
	Prefixes           []string
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

// GetObjectReader streams object data plus its resolved metadata. Callers
// MUST Close it.
type GetObjectReader struct {
	ObjInfo ObjectInfo
	io.ReadCloser
}

// PutObjReader wraps the incoming object data with its expected size. In M2+
// it also carries hash verification (md5/sha256) like MinIO's hash.Reader.
type PutObjReader struct {
	io.Reader
	size       int64
	actualSize int64
}

// NewPutObjReader builds a PutObjReader. actualSize may be -1 when unknown
// (streaming/chunked uploads).
func NewPutObjReader(r io.Reader, size, actualSize int64) *PutObjReader {
	return &PutObjReader{Reader: r, size: size, actualSize: actualSize}
}

// Size is the number of bytes the backend should persist.
func (p *PutObjReader) Size() int64 { return p.size }

// ActualSize is the logical object size (pre-compression/encryption), or -1.
func (p *PutObjReader) ActualSize() int64 { return p.actualSize }

// HTTPRangeSpec models a single HTTP Range header spec.
type HTTPRangeSpec struct {
	// IsSuffixLength: if true, Start is a negative suffix length (bytes=-N).
	IsSuffixLength bool
	Start          int64
	End            int64 // inclusive; -1 means "to end"
}

// ---------------------------------------------------------------------------
// Storage / health info
// ---------------------------------------------------------------------------

// StorageInfo aggregates capacity across all backing disks.
type StorageInfo struct {
	Disks []DiskMetrics
	// Backend describes the deployment shape.
	Backend struct {
		Type             string // "single" | "erasure"
		StandardSCParity int
		RRSCParity       int
	}
}

// DiskMetrics is per-disk capacity/health.
type DiskMetrics struct {
	Endpoint   string
	RootDisk   bool
	State      string // "ok" | "offline" | "corrupt" | "missing"
	TotalSpace uint64
	UsedSpace  uint64
	FreeSpace  uint64
	PoolIndex  int
	SetIndex   int
	DiskIndex  int
}

// HealthOptions / HealthResult back the Health probe used by readiness checks.
type HealthOptions struct {
	Maintenance bool
}

type HealthResult struct {
	Healthy       bool
	HealingDrives int
	WriteQuorum   int
	Reason        string
}
