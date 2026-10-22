package api

import (
	"errors"

	"github.com/lojadopocket/gostore/internal/object"
)

// toAPIError maps a backend error onto an S3 API error code.
func toAPIError(err error) APIErrorCode {
	switch {
	case err == nil:
		return ErrNone
	case errors.Is(err, object.ErrBucketNotFound):
		return ErrNoSuchBucket
	case errors.Is(err, object.ErrBucketExists):
		return ErrBucketAlreadyOwnedByYou
	case errors.Is(err, object.ErrBucketNotEmpty):
		return ErrBucketNotEmpty
	case errors.Is(err, object.ErrBucketNameInvalid):
		return ErrInvalidBucketName
	case errors.Is(err, object.ErrObjectNotFound):
		return ErrNoSuchKey
	case errors.Is(err, object.ErrObjectNameInvalid):
		return ErrInvalidArgument
	case errors.Is(err, object.ErrObjectExistsAsDir):
		return ErrInvalidArgument
	case errors.Is(err, object.ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, object.ErrInvalidRange):
		return ErrInvalidRange
	case errors.Is(err, object.ErrIncompleteBody):
		return ErrIncompleteBody
	case errors.Is(err, object.ErrEntityTooLarge):
		return ErrEntityTooLarge
	case errors.Is(err, object.ErrInvalidUploadID):
		return ErrNoSuchUpload
	case errors.Is(err, object.ErrInvalidPart):
		return ErrInvalidPart
	case errors.Is(err, object.ErrInvalidPartOrder):
		return ErrInvalidPartOrder
	case errors.Is(err, object.ErrPartTooSmall):
		return ErrEntityTooSmall
	case errors.Is(err, object.ErrObjectLocked):
		return ErrObjectLockConflict
	case errors.Is(err, object.ErrNotVersioned):
		return ErrInvalidBucketState
	case errors.Is(err, object.ErrSSECKeyRequired):
		return ErrInvalidRequest
	case errors.Is(err, object.ErrSSECKeyMismatch):
		return ErrAccessDenied
	case errors.Is(err, object.ErrNotImplemented):
		return ErrNotImplemented
	case errors.Is(err, object.ErrStorageFull):
		return ErrSlowDown
	default:
		return ErrInternalError
	}
}
