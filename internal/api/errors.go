package api

import (
	"encoding/xml"
	"net/http"

	"github.com/lojadopocket/gostore/internal/metrics"
)

// APIErrorCode enumerates the S3 error codes we can emit. The subset here
// covers M0–M3; more are added as features land.
type APIErrorCode int

const (
	ErrNone APIErrorCode = iota
	ErrAccessDenied
	ErrBadDigest
	ErrEntityTooSmall
	ErrEntityTooLarge
	ErrIncompleteBody
	ErrInternalError
	ErrInvalidAccessKeyID
	ErrInvalidBucketName
	ErrInvalidDigest
	ErrInvalidRange
	ErrInvalidArgument
	ErrInvalidMaxKeys
	ErrInvalidPart
	ErrInvalidPartOrder
	ErrInvalidRequest
	ErrMalformedXML
	ErrMissingContentLength
	ErrMissingRequestBodyError
	ErrNoSuchBucket
	ErrNoSuchKey
	ErrNoSuchUpload
	ErrNotImplemented
	ErrPreconditionFailed
	ErrRequestTimeTooSkewed
	ErrSignatureDoesNotMatch
	ErrMethodNotAllowed
	ErrBucketNotEmpty
	ErrBucketAlreadyOwnedByYou
	ErrBucketAlreadyExists
	ErrMissingSecurityHeader
	ErrAuthHeaderEmpty
	ErrUnsupportedSignatureVersion
	ErrMissingDateHeader
	ErrSlowDown
	ErrNoSuchBucketPolicy
	ErrNoSuchCORSConfiguration
	ErrNoSuchTagSet
	ErrNoSuchObjectLockConfiguration
	ErrObjectLockConflict
	ErrInvalidBucketState
	ErrNoSuchLifecycleConfiguration
	ErrQuotaExceeded
	ErrMalformedPOSTRequest
	ErrInvalidPolicyDocument
	ErrNoSuchWebsiteConfiguration
	ErrNoSuchEncryptionConfiguration
	ErrInvalidWriteOffset
	ErrServerReadOnly
	ErrBusy
)

// APIError is the resolved (code, message, http status) triple.
type APIError struct {
	Code           string
	Description    string
	HTTPStatusCode int
}

var errorCodeMap = map[APIErrorCode]APIError{
	ErrAccessDenied:                  {"AccessDenied", "Access Denied.", http.StatusForbidden},
	ErrBadDigest:                     {"BadDigest", "The Content-Md5 you specified did not match what we received.", http.StatusBadRequest},
	ErrEntityTooSmall:                {"EntityTooSmall", "Your proposed upload is smaller than the minimum allowed object size.", http.StatusBadRequest},
	ErrEntityTooLarge:                {"EntityTooLarge", "Your proposed upload exceeds the maximum allowed object size.", http.StatusBadRequest},
	ErrIncompleteBody:                {"IncompleteBody", "You did not provide the number of bytes specified by the Content-Length HTTP header.", http.StatusBadRequest},
	ErrInternalError:                 {"InternalError", "We encountered an internal error, please try again.", http.StatusInternalServerError},
	ErrInvalidAccessKeyID:            {"InvalidAccessKeyId", "The Access Key Id you provided does not exist in our records.", http.StatusForbidden},
	ErrInvalidBucketName:             {"InvalidBucketName", "The specified bucket is not valid.", http.StatusBadRequest},
	ErrInvalidDigest:                 {"InvalidDigest", "The Content-Md5 you specified is not valid.", http.StatusBadRequest},
	ErrInvalidRange:                  {"InvalidRange", "The requested range is not satisfiable.", http.StatusRequestedRangeNotSatisfiable},
	ErrInvalidArgument:               {"InvalidArgument", "Invalid argument.", http.StatusBadRequest},
	ErrInvalidMaxKeys:                {"InvalidArgument", "Argument max-keys must be an integer between 0 and 2147483647.", http.StatusBadRequest},
	ErrInvalidPart:                   {"InvalidPart", "One or more of the specified parts could not be found.", http.StatusBadRequest},
	ErrInvalidPartOrder:              {"InvalidPartOrder", "The list of parts was not in ascending order.", http.StatusBadRequest},
	ErrInvalidRequest:                {"InvalidRequest", "Invalid Request.", http.StatusBadRequest},
	ErrMalformedXML:                  {"MalformedXML", "The XML you provided was not well-formed or did not validate against our schema.", http.StatusBadRequest},
	ErrMissingContentLength:          {"MissingContentLength", "You must provide the Content-Length HTTP header.", http.StatusLengthRequired},
	ErrMissingRequestBodyError:       {"MissingRequestBodyError", "Request body is empty.", http.StatusLengthRequired},
	ErrNoSuchBucket:                  {"NoSuchBucket", "The specified bucket does not exist.", http.StatusNotFound},
	ErrNoSuchKey:                     {"NoSuchKey", "The specified key does not exist.", http.StatusNotFound},
	ErrNoSuchUpload:                  {"NoSuchUpload", "The specified multipart upload does not exist.", http.StatusNotFound},
	ErrNotImplemented:                {"NotImplemented", "A header or feature you provided implies functionality that is not implemented.", http.StatusNotImplemented},
	ErrPreconditionFailed:            {"PreconditionFailed", "At least one of the preconditions you specified did not hold.", http.StatusPreconditionFailed},
	ErrRequestTimeTooSkewed:          {"RequestTimeTooSkewed", "The difference between the request time and the server's time is too large.", http.StatusForbidden},
	ErrSignatureDoesNotMatch:         {"SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided.", http.StatusForbidden},
	ErrMethodNotAllowed:              {"MethodNotAllowed", "The specified method is not allowed against this resource.", http.StatusMethodNotAllowed},
	ErrBucketNotEmpty:                {"BucketNotEmpty", "The bucket you tried to delete is not empty.", http.StatusConflict},
	ErrBucketAlreadyOwnedByYou:       {"BucketAlreadyOwnedByYou", "Your previous request to create the named bucket succeeded and you already own it.", http.StatusConflict},
	ErrBucketAlreadyExists:           {"BucketAlreadyExists", "The requested bucket name is not available.", http.StatusConflict},
	ErrMissingSecurityHeader:         {"MissingSecurityHeader", "Your request is missing a required header.", http.StatusBadRequest},
	ErrAuthHeaderEmpty:               {"InvalidArgument", "Authorization header is invalid -- one and only one ' ' (space) required.", http.StatusBadRequest},
	ErrUnsupportedSignatureVersion:   {"InvalidRequest", "The authorization mechanism you have provided is not supported.", http.StatusBadRequest},
	ErrMissingDateHeader:             {"AccessDenied", "AWS authentication requires a valid Date or x-amz-date header.", http.StatusForbidden},
	ErrSlowDown:                      {"SlowDown", "Resource requested is unreadable, please reduce your request rate.", http.StatusServiceUnavailable},
	ErrNoSuchBucketPolicy:            {"NoSuchBucketPolicy", "The bucket policy does not exist.", http.StatusNotFound},
	ErrNoSuchCORSConfiguration:       {"NoSuchCORSConfiguration", "The CORS configuration does not exist.", http.StatusNotFound},
	ErrNoSuchTagSet:                  {"NoSuchTagSet", "The TagSet does not exist.", http.StatusNotFound},
	ErrNoSuchObjectLockConfiguration: {"ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket.", http.StatusNotFound},
	ErrObjectLockConflict:            {"AccessDenied", "Access Denied because the object is protected by object lock (retention or legal hold).", http.StatusForbidden},
	ErrInvalidBucketState:            {"InvalidBucketState", "The request is not valid for the current state of the bucket.", http.StatusConflict},
	ErrNoSuchLifecycleConfiguration:  {"NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist.", http.StatusNotFound},
	ErrQuotaExceeded:                 {"QuotaExceeded", "The bucket quota would be exceeded by this operation.", http.StatusForbidden},
	ErrMalformedPOSTRequest:          {"MalformedPOSTRequest", "The body of your POST request is not well-formed multipart/form-data.", http.StatusBadRequest},
	ErrInvalidPolicyDocument:         {"InvalidPolicyDocument", "The content of the form does not meet the conditions specified in the policy document.", http.StatusForbidden},
	ErrNoSuchWebsiteConfiguration:    {"NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration.", http.StatusNotFound},
	ErrNoSuchEncryptionConfiguration: {"ServerSideEncryptionConfigurationNotFoundError", "The server side encryption configuration was not found.", http.StatusNotFound},
	ErrInvalidWriteOffset:            {"InvalidWriteOffset", "The write offset must equal the current object size.", http.StatusConflict},
	ErrServerReadOnly:                {"ServerReadOnly", "The server is in read-only mode; writes are temporarily rejected.", http.StatusServiceUnavailable},
	ErrBusy:                          {"SlowDown", "The server is shedding load; retry shortly.", http.StatusServiceUnavailable},
}

// GetAPIError resolves a code; unknown codes fall back to InternalError.
func GetAPIError(code APIErrorCode) APIError {
	if e, ok := errorCodeMap[code]; ok {
		return e
	}
	return errorCodeMap[ErrInternalError]
}

// errorResponse is the S3 XML error envelope.
type errorResponse struct {
	XMLName    xml.Name `xml:"Error"`
	Code       string   `xml:"Code"`
	Message    string   `xml:"Message"`
	Resource   string   `xml:"Resource"`
	RequestID  string   `xml:"RequestId"`
	BucketName string   `xml:"BucketName,omitempty"`
	Key        string   `xml:"Key,omitempty"`
}

// writeErrorResponse emits an S3-style XML error.
func writeErrorResponse(w http.ResponseWriter, r *http.Request, code APIErrorCode, resource string) {
	ae := GetAPIError(code)
	metrics.APIError(ae.Code)
	resp := errorResponse{
		Code:      ae.Code,
		Message:   ae.Description,
		Resource:  resource,
		RequestID: requestIDFrom(r),
	}
	body, err := xml.Marshal(resp)
	if err != nil {
		http.Error(w, ae.Description, ae.HTTPStatusCode)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", resp.RequestID)
	w.Header().Set("x-gostore-error", ae.Code) // picked up by the activity feed
	w.WriteHeader(ae.HTTPStatusCode)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}
