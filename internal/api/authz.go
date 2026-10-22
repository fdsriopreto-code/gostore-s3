package api

import (
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/lojadopocket/gostore/internal/iam/policy"
	"github.com/lojadopocket/gostore/internal/logger"
)

// bucketPolicyCache memoises the parsed form of each bucket's policy document.
// Without it every request that reaches the bucket-policy check (notably every
// GET against a public bucket) re-runs a JSON unmarshal + policy compile.
// Keyed by bucket; the stored raw text is compared on lookup so an edited
// policy is recompiled automatically — one entry per bucket, no eviction
// needed.
type bucketPolicyCache struct {
	mu sync.RWMutex
	m  map[string]compiledPolicy
}

type compiledPolicy struct {
	raw string
	pol *policy.Policy // nil when the document failed to parse
}

func newBucketPolicyCache() *bucketPolicyCache {
	return &bucketPolicyCache{m: map[string]compiledPolicy{}}
}

// get returns the compiled policy for doc, parsing and caching on a miss or
// when the document has changed since it was cached. ok is false when doc is
// empty or does not parse.
func (c *bucketPolicyCache) get(bucket string, doc []byte) (*policy.Policy, bool) {
	if len(doc) == 0 {
		return nil, false
	}
	raw := string(doc)
	c.mu.RLock()
	e, hit := c.m[bucket]
	c.mu.RUnlock()
	if hit && e.raw == raw {
		return e.pol, e.pol != nil
	}
	p, err := policy.Parse(doc)
	if err != nil {
		p = nil
	}
	c.mu.Lock()
	c.m[bucket] = compiledPolicy{raw: raw, pol: p}
	c.mu.Unlock()
	return p, p != nil
}

// authorizeS3 decides whether the request may proceed. Order:
//  1. IAM policy of the authenticated user (root always passes);
//  2. the bucket policy (covers anonymous / cross-account public access);
//  3. GOSTORE_ALLOW_ANONYMOUS=1 as a dev-mode escape hatch.
func (s *Server) authorizeS3(r *http.Request, req s3Request, q map[string][]string, accessKey string) APIErrorCode {
	return s.authorizeAction(r, accessKey, s3Action(r, req, q), req.Bucket, req.Object, map[string][]string{
		"s3:prefix": first(q["prefix"]),
	})
}

// authorizeAction is the single authorization gate: it evaluates one S3 action
// against a (bucket, object) for the caller, trying the caller's IAM policy,
// then the bucket policy (anonymous / public access), then the dev-mode
// anonymous escape hatch. Both the request path and internal checks (e.g. the
// read of a CopyObject source) go through here so the rules stay in one place.
func (s *Server) authorizeAction(r *http.Request, accessKey, action, bucket, object string, cond map[string][]string) APIErrorCode {
	args := policy.Args{
		AccountName:     accessKey,
		Action:          action,
		BucketName:      bucket,
		ObjectName:      object,
		SourceIP:        clientIP(r),
		ConditionValues: cond,
	}
	if accessKey != "" && s.iam.IsAllowed(accessKey, args) {
		return ErrNone
	}
	if s.bucketPolicyAllows(bucket, args) {
		return ErrNone
	}
	if accessKey == "" && os.Getenv("GOSTORE_ALLOW_ANONYMOUS") == "1" {
		return ErrNone
	}
	return ErrAccessDenied
}

// authorizeCopySource checks that the caller may read a CopyObject /
// UploadPartCopy source. It honours the copySrcAuthz mode so an existing
// deployment can roll the check out without breaking in-flight workloads:
// "warn" logs and allows, "off" skips, "enforce" (default) denies. It returns
// the error code to emit (ErrNone to proceed).
func (s *Server) authorizeCopySource(r *http.Request, accessKey, srcBucket, srcKey string) APIErrorCode {
	if s.copySrcAuthz == "off" {
		return ErrNone
	}
	if code := s.authorizeAction(r, accessKey, "s3:GetObject", srcBucket, srcKey, nil); code != ErrNone {
		if s.copySrcAuthz == "warn" {
			logger.Warn("copy-source read not authorized (compat warn mode: allowing; set GOSTORE_COPY_SOURCE_AUTHZ=enforce to block)",
				"accessKey", accessKey, "srcBucket", srcBucket, "srcKey", srcKey)
			return ErrNone
		}
		return code
	}
	return ErrNone
}

// bucketPolicyAllows evaluates the bucket's own policy document (if any).
func (s *Server) bucketPolicyAllows(bucket string, args policy.Args) bool {
	if bucket == "" || s.bcfg == nil {
		return false
	}
	p, ok := s.polCache.get(bucket, s.bcfg.Get(bucket).Policy)
	if !ok {
		return false
	}
	return p.IsAllowed(args)
}

func first(v []string) []string {
	if len(v) == 0 {
		return []string{""}
	}
	return v[:1]
}

// accessKeyFrom returns the authenticated access key stashed by handleS3.
func accessKeyFrom(r *http.Request) string {
	if v, ok := r.Context().Value(ctxKeyAccessKey{}).(string); ok {
		return v
	}
	return ""
}

// clientIP returns the caller's source IP, used for IpAddress policy
// conditions and per-IP rate limiting. X-Forwarded-For is only honoured when
// the direct peer (RemoteAddr) is a trusted proxy — otherwise any client
// could spoof its source IP just by sending the header. When trusted, the
// header is walked right-to-left skipping further trusted proxies, so the
// first untrusted hop (the address the edge proxy actually saw) wins and a
// client cannot forge it by prepending entries.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !isTrustedProxy(net.ParseIP(host)) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ipStr := strings.TrimSpace(parts[i])
		ip := net.ParseIP(ipStr)
		if ip == nil || isTrustedProxy(ip) {
			continue
		}
		return ipStr
	}
	return host
}

var (
	trustedProxyOnce sync.Once
	trustedProxyNets []*net.IPNet
)

// isTrustedProxy reports whether ip is an allowed reverse proxy, so its
// X-Forwarded-For may be believed. GOSTORE_TRUSTED_PROXIES overrides the set
// (comma-separated CIDRs or bare IPs). Unset, it defaults to loopback and the
// private ranges, which is where a reverse proxy (nginx/Traefik/PaaS) sits —
// a spoofing client on the public internet has a public RemoteAddr and is
// therefore never trusted.
func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	trustedProxyOnce.Do(func() {
		v := strings.TrimSpace(os.Getenv("GOSTORE_TRUSTED_PROXIES"))
		if v == "" {
			for _, c := range []string{
				"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12",
				"192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10",
			} {
				if _, n, err := net.ParseCIDR(c); err == nil {
					trustedProxyNets = append(trustedProxyNets, n)
				}
			}
			return
		}
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !strings.Contains(part, "/") {
				if pip := net.ParseIP(part); pip != nil {
					bits := 128
					if pip.To4() != nil {
						bits = 32
					}
					trustedProxyNets = append(trustedProxyNets, &net.IPNet{IP: pip, Mask: net.CIDRMask(bits, bits)})
				}
				continue
			}
			if _, n, err := net.ParseCIDR(part); err == nil {
				trustedProxyNets = append(trustedProxyNets, n)
			}
		}
	})
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// s3Action maps an HTTP request to its S3 IAM action name.
func s3Action(r *http.Request, req s3Request, q map[string][]string) string {
	has := func(k string) bool { _, ok := q[k]; return ok }

	switch {
	case req.Bucket == "":
		return "s3:ListAllMyBuckets"

	case req.Object == "":
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			switch {
			case has("location"):
				return "s3:GetBucketLocation"
			case has("uploads"):
				return "s3:ListBucketMultipartUploads"
			case has("versioning"):
				return "s3:GetBucketVersioning"
			case has("policy"):
				return "s3:GetBucketPolicy"
			case has("tagging"):
				return "s3:GetBucketTagging"
			case has("cors"):
				return "s3:GetBucketCORS"
			case has("object-lock"):
				return "s3:GetBucketObjectLockConfiguration"
			case has("replication"):
				return "s3:GetReplicationConfiguration"
			case has("lifecycle"):
				return "s3:GetLifecycleConfiguration"
			case has("notification"):
				return "s3:GetBucketNotification"
			case has("website"):
				return "s3:GetBucketWebsite"
			case has("compression"):
				return "s3:GetBucketCompression"
			case has("encryption"):
				return "s3:GetEncryptionConfiguration"
			case has("quota"):
				return "s3:GetBucketQuota"
			default:
				return "s3:ListBucket"
			}
		case http.MethodPut:
			switch {
			case has("versioning"):
				return "s3:PutBucketVersioning"
			case has("policy"):
				return "s3:PutBucketPolicy"
			case has("tagging"):
				return "s3:PutBucketTagging"
			case has("cors"):
				return "s3:PutBucketCORS"
			case has("object-lock"):
				return "s3:PutBucketObjectLockConfiguration"
			case has("replication"):
				return "s3:PutReplicationConfiguration"
			case has("lifecycle"):
				return "s3:PutLifecycleConfiguration"
			case has("notification"):
				return "s3:PutBucketNotification"
			case has("website"):
				return "s3:PutBucketWebsite"
			case has("compression"):
				return "s3:PutBucketCompression"
			case has("encryption"):
				return "s3:PutEncryptionConfiguration"
			case has("quota"):
				return "s3:PutBucketQuota"
			case has("acl"):
				return "s3:PutBucketAcl"
			default:
				return "s3:CreateBucket"
			}
		case http.MethodDelete:
			switch {
			case has("policy"):
				return "s3:DeleteBucketPolicy"
			case has("tagging"):
				return "s3:PutBucketTagging"
			case has("cors"):
				return "s3:PutBucketCORS"
			case has("replication"):
				return "s3:PutReplicationConfiguration"
			case has("lifecycle"):
				return "s3:PutLifecycleConfiguration"
			case has("website"):
				return "s3:PutBucketWebsite"
			case has("encryption"):
				return "s3:PutEncryptionConfiguration"
			case has("quota"):
				return "s3:PutBucketQuota"
			default:
				return "s3:DeleteBucket"
			}
		case http.MethodPost:
			if has("delete") {
				return "s3:DeleteObject"
			}
		}
		return "s3:ListBucket"

	default: // object-level
		switch r.Method {
		case http.MethodGet:
			if has("uploadId") {
				return "s3:ListMultipartUploadParts"
			}
			if has("tagging") {
				return "s3:GetObjectTagging"
			}
			if has("retention") {
				return "s3:GetObjectRetention"
			}
			if has("legal-hold") {
				return "s3:GetObjectLegalHold"
			}
			return "s3:GetObject"
		case http.MethodHead:
			return "s3:GetObject"
		case http.MethodPut:
			if has("tagging") {
				return "s3:PutObjectTagging"
			}
			if has("retention") {
				return "s3:PutObjectRetention"
			}
			if has("legal-hold") {
				return "s3:PutObjectLegalHold"
			}
			// CopyObject / UploadPartCopy: the write is s3:PutObject on the
			// destination; the caller's read access to the source is checked
			// separately in the copy handlers (s3:GetObject on the source).
			return "s3:PutObject"
		case http.MethodPost:
			if has("uploads") || has("uploadId") {
				return "s3:PutObject"
			}
		case http.MethodDelete:
			if has("uploadId") {
				return "s3:AbortMultipartUpload"
			}
			if has("tagging") {
				return "s3:DeleteObjectTagging"
			}
			return "s3:DeleteObject"
		}
		return "s3:GetObject"
	}
}
