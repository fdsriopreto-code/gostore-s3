package api

import "strings"

// sysPrefix is the reserved on-disk namespace. No S3-visible key may name it,
// or a request could reach the IAM store, bucket config, disk format, etc.
const sysPrefix = ".gostore.sys"

// validObjectKey rejects object keys that could escape the bucket directory or
// reach the reserved system namespace. It mirrors the backends' own
// validObjectName but runs at the API boundary so every path — including the
// batch DeleteObjects body and the x-amz-copy-source header, which do not go
// through the per-object PUT validation — is covered before a key is handed to
// a backend. The rules match S3's object-key constraints plus gostore's
// reserved-prefix rule.
func validObjectKey(name string) bool {
	if name == "" || len(name) > 1024 || strings.Contains(name, "\x00") {
		return false
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return !strings.HasPrefix(name, sysPrefix+"/") && name != sysPrefix
}

// validBucket applies the DNS-subset bucket naming rules and rejects the
// reserved system bucket. Used to validate names that arrive outside the
// normal request path (notably a CopyObject source).
func validBucket(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") ||
		strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") ||
		strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return name != sysPrefix
}
