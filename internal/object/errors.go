package object

import (
	"errors"
	"fmt"
)

// Sentinel errors returned by Layer implementations. internal/api maps these
// to S3 error codes (see internal/api/errors.go). They are deliberately
// backend-agnostic.
var (
	ErrNotImplemented = errors.New("object: not implemented in this milestone")

	ErrBucketNotFound    = errors.New("object: bucket not found")
	ErrBucketExists      = errors.New("object: bucket already exists")
	ErrBucketNotEmpty    = errors.New("object: bucket not empty")
	ErrBucketNameInvalid = errors.New("object: invalid bucket name")

	ErrObjectNotFound     = errors.New("object: object not found")
	ErrObjectNameInvalid  = errors.New("object: invalid object name")
	ErrObjectExistsAsDir  = errors.New("object: object name already exists as a directory prefix")
	ErrPreconditionFailed = errors.New("object: precondition failed")
	ErrInvalidRange       = errors.New("object: invalid range")
	ErrIncompleteBody     = errors.New("object: fewer bytes than declared Content-Length")
	ErrEntityTooLarge     = errors.New("object: object exceeds the maximum allowed size")

	ErrInvalidUploadID  = errors.New("object: invalid or unknown upload id")
	ErrInvalidPart      = errors.New("object: one or more parts are invalid")
	ErrPartTooSmall     = errors.New("object: part smaller than the minimum allowed size")
	ErrInvalidPartOrder = errors.New("object: parts not in ascending order")

	ErrObjectLocked = errors.New("object: blocked by object-lock retention or legal hold")
	ErrNotVersioned = errors.New("object: bucket is not versioned")

	// SSE-C: the object was stored with a customer key and the read either
	// supplied no key or the wrong one.
	ErrSSECKeyRequired = errors.New("object: object is SSE-C encrypted; a customer key is required")
	ErrSSECKeyMismatch = errors.New("object: SSE-C customer key does not match the key the object was encrypted with")

	ErrStorageFull   = errors.New("object: storage backend is full")
	ErrReadQuorum    = errors.New("object: not enough healthy disks for read quorum")
	ErrWriteQuorum   = errors.New("object: not enough healthy disks for write quorum")
	ErrCorruptedData = errors.New("object: data failed integrity check (bitrot)")
)

// BucketNotFound et al. are typed wrappers so handlers can attach the offending
// name while still matching via errors.Is against the sentinels above.

type BucketNotFound struct{ Bucket string }

func (e BucketNotFound) Error() string { return fmt.Sprintf("object: bucket %q not found", e.Bucket) }
func (e BucketNotFound) Unwrap() error { return ErrBucketNotFound }

type ObjectNotFound struct{ Bucket, Object string }

func (e ObjectNotFound) Error() string {
	return fmt.Sprintf("object: %s/%s not found", e.Bucket, e.Object)
}
func (e ObjectNotFound) Unwrap() error { return ErrObjectNotFound }

type BucketExists struct{ Bucket string }

func (e BucketExists) Error() string {
	return fmt.Sprintf("object: bucket %q already exists", e.Bucket)
}
func (e BucketExists) Unwrap() error { return ErrBucketExists }
