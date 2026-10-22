package api

import (
	"crypto/md5"
	"encoding/base64"
	"net/http"
)

// parseSSEC reads the S3 SSE-C request headers (customer-provided encryption
// key). It returns the 32-byte key and its base64 MD5 when present and valid.
// When no SSE-C header is present it returns (nil, "", ErrNone). Any malformed
// combination (bad algorithm, key not 32 bytes, MD5 mismatch) is ErrInvalidArgument.
func parseSSEC(r *http.Request) (key []byte, keyMD5 string, code APIErrorCode) {
	alg := r.Header.Get("x-amz-server-side-encryption-customer-algorithm")
	keyB64 := r.Header.Get("x-amz-server-side-encryption-customer-key")
	md5B64 := r.Header.Get("x-amz-server-side-encryption-customer-key-MD5")
	if alg == "" && keyB64 == "" && md5B64 == "" {
		return nil, "", ErrNone
	}
	if alg != "AES256" {
		return nil, "", ErrInvalidArgument
	}
	k, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(k) != 32 {
		return nil, "", ErrInvalidArgument
	}
	sum := md5.Sum(k)
	want := base64.StdEncoding.EncodeToString(sum[:])
	if md5B64 == "" || md5B64 != want {
		return nil, "", ErrInvalidArgument
	}
	return k, want, ErrNone
}
