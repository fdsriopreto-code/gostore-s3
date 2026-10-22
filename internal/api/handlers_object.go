package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/lojadopocket/gostore/internal/bufpool"
	"github.com/lojadopocket/gostore/internal/event"
	"github.com/lojadopocket/gostore/internal/object"
	"github.com/lojadopocket/gostore/internal/replication"
)

const maxSinglePutSize = 5 * 1024 * 1024 * 1024 // 5 GiB (S3 single-PUT limit)

func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	size := bodySize(r)
	if size < 0 {
		writeErrorResponse(w, r, ErrMissingContentLength, "/"+bucket+"/"+key)
		return
	}
	if size > maxSinglePutSize {
		writeErrorResponse(w, r, ErrEntityTooLarge, "/"+bucket+"/"+key)
		return
	}
	if s.quotaExceeded(bucket, size) {
		writeErrorResponse(w, r, ErrQuotaExceeded, "/"+bucket+"/"+key)
		return
	}

	// Append: x-amz-write-offset-bytes turns this PUT into an append at the
	// given offset (which must equal the current object size).
	if r.Header.Get("x-amz-write-offset-bytes") != "" {
		s.handleAppendObject(w, r, bucket, key, size)
		return
	}

	opts := s.vopts(bucket, r)
	opts.UserDefined = extractMetadata(r, key)
	// SSE-C: a customer-provided key encrypts this object; the server never
	// stores it. Takes precedence over (and suppresses) default encryption.
	if ck, cmd5, code := parseSSEC(r); code != ErrNone {
		writeErrorResponse(w, r, code, "/"+bucket+"/"+key)
		return
	} else if ck != nil {
		opts.SSECustomerKey = ck
		opts.SSECustomerKeyMD5 = cmd5
	} else {
		s.applyDefaultEncryption(bucket, opts.UserDefined)
	}
	if v := r.Header.Get("x-amz-tagging"); v != "" {
		opts.UserTags = v
	}
	// Per-object TTL (gostore extension): store an absolute expiry instant the
	// scanner and GET path enforce — no bucket lifecycle rule needed.
	if exp := parseExpiryDirective(r.Header.Get, time.Now()); !exp.IsZero() {
		opts.UserDefined[expiryMetaKey] = exp.Format(time.RFC3339)
	}
	// Conditional writes (S3 / RFC 7232). CheckPrecondFn returns true to mean
	// "precondition failed, abort with 412"; the backend only calls it when
	// the object already exists.
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if inm == "*" {
			// Atomic create-if-absent.
			opts.CheckPrecondFn = func(oi object.ObjectInfo) bool { return oi.Name != "" && oi.ETag != "" }
		} else {
			opts.CheckPrecondFn = func(oi object.ObjectInfo) bool {
				return etagMatches(inm, strings.Trim(oi.ETag, `"`))
			}
		}
	} else if im := r.Header.Get("If-Match"); im != "" {
		// If-Match requires the object to exist; the backend won't run the
		// precondition fn when it doesn't, so pre-check.
		if cur, err := s.obj.GetObjectInfo(r.Context(), bucket, key, object.ObjectOptions{}); err != nil {
			writeErrorResponse(w, r, ErrPreconditionFailed, "/"+bucket+"/"+key)
			return
		} else if im != "*" && !etagMatches(im, strings.Trim(cur.ETag, `"`)) {
			writeErrorResponse(w, r, ErrPreconditionFailed, "/"+bucket+"/"+key)
			return
		}
		opts.CheckPrecondFn = func(oi object.ObjectInfo) bool {
			return im != "*" && !etagMatches(im, strings.Trim(oi.ETag, `"`))
		}
	}

	// Additional checksum (x-amz-checksum-<algo>): verify inline as the body
	// streams; a mismatch aborts the write.
	body := io.Reader(r.Body)
	if algo, want := checksumFromHeaders(r.Header); algo != "" {
		body = newVerifyingReader(r.Body, algo, want)
		// Stored under an x-amz-meta- key so both backends keep it; echoed as
		// x-amz-checksum-<algo> on read (see writeObjectHeaders).
		opts.UserDefined["x-amz-meta-checksum-"+algo] = want
	}

	oi, err := s.obj.PutObject(r.Context(), bucket, key, object.NewPutObjReader(body, size, size), opts)
	if err != nil {
		var ce *checksumError
		if errors.As(err, &ce) {
			writeErrorResponse(w, r, ErrBadDigest, "/"+bucket+"/"+key)
			return
		}
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	w.Header().Set("ETag", quoteETag(oi.ETag))
	if oi.VersionID != "" {
		w.Header().Set("x-amz-version-id", oi.VersionID)
	}
	if v := oi.UserDefined["x-amz-server-side-encryption"]; v != "" {
		w.Header().Set("x-amz-server-side-encryption", v)
	}
	s.notify(r, event.ObjectCreated, bucket, key, oi.Size, oi.ETag)
	writeSuccessOK(w)
}

func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.getOrHeadObject(w, r, bucket, key, true)
}

func (s *Server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	s.getOrHeadObject(w, r, bucket, key, false)
}

func (s *Server) getOrHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string, withBody bool) {
	res := "/" + bucket + "/" + key
	gopts := s.vopts(bucket, r)

	// SSE-C: carry the customer key to the backend for decryption.
	ck, cmd5, code := parseSSEC(r)
	if code != ErrNone {
		writeErrorResponse(w, r, code, res)
		return
	}
	ssec := ck != nil
	if ssec {
		gopts.SSECustomerKey = ck
		gopts.SSECustomerKeyMD5 = cmd5
	}

	// Hot-object cache fast path: whole-object GET/HEAD of the current version,
	// served from RAM with no backend call. SSE-C objects are NEVER cached —
	// the plaintext must never be reachable without presenting the key.
	cacheable := gopts.VersionID == "" && r.Header.Get("Range") == "" && !ssec
	if cacheable && s.ocache.enabled() {
		if e, ok := s.ocache.get(cacheKey(bucket, key, "")); ok {
			if objectHasExpired(e.info.UserDefined, time.Now()) {
				s.ocache.evict(bucket, key, "")
			} else {
				s.serveCached(w, r, e, withBody)
				return
			}
		}
	}

	oi, err := s.obj.GetObjectInfo(r.Context(), bucket, key, gopts)
	if err != nil {
		if oi.DeleteMarker {
			w.Header().Set("x-amz-delete-marker", "true")
		}
		writeErrorResponse(w, r, toAPIError(err), res)
		return
	}
	if oi.VersionID != "" {
		w.Header().Set("x-amz-version-id", oi.VersionID)
	}

	// Per-object TTL: an expired object reads as gone and is deleted in the
	// background (the scanner sweeps any the read path never revisits).
	if objectHasExpired(oi.UserDefined, time.Now()) {
		go func() {
			_, _ = s.obj.DeleteObject(context.Background(), bucket, key, object.ObjectOptions{})
		}()
		writeErrorResponse(w, r, ErrNoSuchKey, res)
		return
	}

	// SSE-C: an object stored with a customer key can only be read (GET or
	// HEAD) by presenting that same key. Validate here so HEAD — which never
	// calls the decrypting read path — is enforced too.
	if objMD5 := oi.UserDefined["x-amz-server-side-encryption-customer-key-md5"]; objMD5 != "" {
		if !ssec {
			writeErrorResponse(w, r, ErrInvalidRequest, res)
			return
		}
		if cmd5 != objMD5 {
			writeErrorResponse(w, r, ErrAccessDenied, res)
			return
		}
	}

	switch condStatus := evalGetConditionals(r, oi); condStatus {
	case http.StatusNotModified:
		writeObjectHeaders(w, oi, s.cfg.Region)
		w.WriteHeader(http.StatusNotModified)
		return
	case http.StatusPreconditionFailed:
		writeErrorResponse(w, r, ErrPreconditionFailed, res)
		return
	}

	var rng *object.HTTPRangeSpec
	if rh := r.Header.Get("Range"); rh != "" && withBody {
		spec, ok := parseRange(rh)
		if !ok {
			w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(oi.Size, 10))
			writeErrorResponse(w, r, ErrInvalidRange, res)
			return
		}
		rng = spec
	}

	writeObjectHeaders(w, oi, s.cfg.Region)

	if !withBody {
		w.Header().Set("Content-Length", strconv.FormatInt(oi.Size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}

	gr, err := s.obj.GetObjectNInfo(r.Context(), bucket, key, rng, r.Header, gopts)
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), res)
		return
	}
	defer gr.Close()

	status := http.StatusOK
	if rng != nil {
		start, length, _ := resolveRangeForHeader(rng, oi.Size)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, start+length-1, oi.Size))
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		status = http.StatusPartialContent
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(oi.Size, 10))
	}
	// Fill the hot-object cache on a full read of an eligible small object:
	// buffer it once, serve it, and keep the copy in RAM.
	if rng == nil && !ssec && s.ocache.eligibleSize(oi.Size) {
		body, rerr := io.ReadAll(gr)
		w.WriteHeader(status)
		_, _ = w.Write(body)
		if rerr == nil && int64(len(body)) == oi.Size {
			s.ocache.put(cacheKey(bucket, key, ""), body, oi)
		}
		return
	}

	w.WriteHeader(status)
	_, _ = bufpool.Copy(w, gr)
}

// serveCached answers a GET/HEAD entirely from a hot-object cache entry.
func (s *Server) serveCached(w http.ResponseWriter, r *http.Request, e *cacheEntry, withBody bool) {
	if e.info.VersionID != "" {
		w.Header().Set("x-amz-version-id", e.info.VersionID)
	}
	switch evalGetConditionals(r, e.info) {
	case http.StatusNotModified:
		writeObjectHeaders(w, e.info, s.cfg.Region)
		w.Header().Set("x-gostore-cache", "HIT")
		w.WriteHeader(http.StatusNotModified)
		return
	case http.StatusPreconditionFailed:
		writeErrorResponse(w, r, ErrPreconditionFailed, r.URL.Path)
		return
	}
	writeObjectHeaders(w, e.info, s.cfg.Region)
	w.Header().Set("x-gostore-cache", "HIT")
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(e.data)), 10))
	if !withBody {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(e.data)
}

func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	di, err := s.obj.DeleteObject(r.Context(), bucket, key, s.vopts(bucket, r))
	if err != nil {
		if ec := toAPIError(err); ec != ErrNoSuchKey { // delete is idempotent
			writeErrorResponse(w, r, ec, "/"+bucket+"/"+key)
			return
		}
	}
	if di.VersionID != "" {
		w.Header().Set("x-amz-version-id", di.VersionID)
	}
	if di.DeleteMarker {
		w.Header().Set("x-amz-delete-marker", "true")
	}
	s.notify(r, event.ObjectRemoved, bucket, key, 0, "")
	writeSuccessNoContent(w)
}

// notify publishes a bucket-notification event and a replication event
// (both no-ops when nothing is configured for the bucket).
func (s *Server) notify(r *http.Request, kind event.Kind, bucket, key string, size int64, etag string) {
	// Every object create/remove flows through here, so this is the single
	// point that keeps the hot-object cache coherent with local writes.
	s.ocache.evict(bucket, key, "")
	if s.bus != nil {
		s.bus.Publish(event.Event{
			Kind: kind, Bucket: bucket, Key: key, Size: size,
			ETag: strings.Trim(etag, `"`), SourceIP: clientIP(r),
		})
	}
	if s.repl != nil {
		op := replication.Put
		if kind == event.ObjectRemoved {
			op = replication.Delete
		}
		s.repl.Publish(replication.Event{Op: op, Bucket: bucket, Key: key})
	}
}

func (s *Server) handleCopyObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	src := r.Header.Get("x-amz-copy-source")
	srcBucket, srcKey, ok := parseCopySource(src)
	if !ok || !validBucket(srcBucket) || !validObjectKey(srcKey) || !validObjectKey(key) {
		writeErrorResponse(w, r, ErrInvalidArgument, "/"+bucket+"/"+key)
		return
	}
	// SSE-C copy (source or dest) is not supported yet.
	if r.Header.Get("x-amz-server-side-encryption-customer-algorithm") != "" ||
		r.Header.Get("x-amz-copy-source-server-side-encryption-customer-algorithm") != "" {
		writeErrorResponse(w, r, ErrNotImplemented, "/"+bucket+"/"+key)
		return
	}

	// The caller must be allowed to READ the source, not just write the
	// destination — otherwise a key with write access to one bucket could
	// copy (and then read) any object from any bucket.
	if code := s.authorizeCopySource(r, accessKeyFrom(r), srcBucket, srcKey); code != ErrNone {
		writeErrorResponse(w, r, code, "/"+srcBucket+"/"+srcKey)
		return
	}

	srcInfo, err := s.obj.GetObjectInfo(r.Context(), srcBucket, srcKey, object.ObjectOptions{})
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+srcBucket+"/"+srcKey)
		return
	}

	dstOpts := object.ObjectOptions{UserDefined: extractMetadata(r, key)}
	s.applyDefaultEncryption(bucket, dstOpts.UserDefined)
	if strings.EqualFold(r.Header.Get("x-amz-metadata-directive"), "REPLACE") {
		dstOpts.UserDefined["_directive"] = "REPLACE"
	}
	if v := r.Header.Get("x-amz-tagging"); v != "" && strings.EqualFold(r.Header.Get("x-amz-tagging-directive"), "REPLACE") {
		dstOpts.UserTags = v
	}

	oi, err := s.obj.CopyObject(r.Context(), srcBucket, srcKey, bucket, key, srcInfo, object.ObjectOptions{}, dstOpts)
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	s.notify(r, event.ObjectCreated, bucket, key, oi.Size, oi.ETag)
	writeXML(w, http.StatusOK, copyObjectResult{
		XMLNS: s3XMLNS, LastModified: amzTime(oi.ModTime), ETag: quoteETag(oi.ETag),
	})
}

// --- helpers -----------------------------------------------------------

func writeObjectHeaders(w http.ResponseWriter, oi object.ObjectInfo, region string) {
	h := w.Header()
	if oi.ETag != "" {
		h.Set("ETag", quoteETag(oi.ETag))
	}
	h.Set("Last-Modified", httpTime(oi.ModTime))
	ct := oi.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	if oi.ContentEncoding != "" {
		h.Set("Content-Encoding", oi.ContentEncoding)
	}
	h.Set("Accept-Ranges", "bytes")
	if oi.VersionID != "" {
		h.Set("x-amz-version-id", oi.VersionID)
	}
	for k, v := range oi.UserDefined {
		lk := strings.ToLower(k)
		if lk == "content-type" || lk == "content-encoding" || lk == "etag" {
			continue
		}
		// Additional checksum: stored as (x-amz-meta-)checksum-<algo>, echoed
		// as the real x-amz-checksum-<algo> header + x-amz-checksum-type.
		if base := strings.TrimPrefix(strings.TrimPrefix(lk, "x-amz-meta-"), "x-amz-"); strings.HasPrefix(base, "checksum-") {
			h.Set("x-amz-"+base, v)
			h.Set("x-amz-checksum-type", "FULL_OBJECT")
			continue
		}
		if lk == "x-amz-server-side-encryption" {
			h.Set("x-amz-server-side-encryption", v)
			continue
		}
		// SSE-C response headers (algorithm + key MD5) are real headers, not
		// user metadata.
		if strings.HasPrefix(lk, "x-amz-server-side-encryption-customer-") {
			h.Set(lk, v)
			continue
		}
		h.Set("x-amz-meta-"+lk, v)
	}
	if oi.UserTags != "" {
		n := 0
		if oi.UserTags != "" {
			n = len(strings.Split(oi.UserTags, "&"))
		}
		h.Set("x-amz-tagging-count", strconv.Itoa(n))
	}
}

// vopts builds ObjectOptions carrying the bucket's versioning state, any
// ?versionId, and object-lock parameters (request headers, else the bucket's
// default retention rule).
func (s *Server) vopts(bucket string, r *http.Request) object.ObjectOptions {
	o := object.ObjectOptions{VersionID: r.URL.Query().Get("versionId")}
	var lockCfg *bucketcfgObjectLock
	if s.bcfg != nil {
		c := s.bcfg.Get(bucket)
		o.Compress = c.Compress
		switch c.Versioning {
		case "Enabled":
			o.Versioned = true
		case "Suspended":
			o.VersionSuspended = true
		}
		if c.ObjectLock != nil && c.ObjectLock.Enabled {
			o.Versioned = true
			lockCfg = &bucketcfgObjectLock{c.ObjectLock.DefaultMode, c.ObjectLock.DefaultDays, c.ObjectLock.DefaultYears}
		}
	}

	if m := r.Header.Get("x-amz-object-lock-mode"); m != "" {
		o.LockMode = m
	}
	if d := r.Header.Get("x-amz-object-lock-retain-until-date"); d != "" {
		if t, err := time.Parse(time.RFC3339, d); err == nil {
			o.LockRetainUntil = t
		}
	}
	if lh := r.Header.Get("x-amz-object-lock-legal-hold"); lh != "" {
		o.LockLegalHold = lh
	}
	// Apply the bucket default only when the request itself said nothing.
	if o.LockMode == "" && lockCfg != nil {
		d := time.Duration(lockCfg.days)*24*time.Hour + time.Duration(lockCfg.years)*365*24*time.Hour
		if lockCfg.mode != "" && d > 0 {
			o.LockMode = lockCfg.mode
			o.LockRetainUntil = time.Now().UTC().Add(d)
		}
	}
	if r.Header.Get("x-amz-bypass-governance-retention") == "true" {
		o.BypassGovernance = s.bypassAllowed(r, bucket, "", accessKeyFrom(r))
	}
	return o
}

type bucketcfgObjectLock struct {
	mode  string
	days  int
	years int
}

// bodySize returns the number of raw object bytes to expect. For aws-chunked
// (STREAMING-*) uploads that is x-amz-decoded-content-length; otherwise the
// Content-Length. Returns -1 when unknown.
func bodySize(r *http.Request) int64 {
	if v := r.Header.Get("x-amz-decoded-content-length"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n
		}
	}
	return r.ContentLength
}

// noSniff disables guessing an object's Content-Type from its key extension
// (GOSTORE_NO_CONTENT_TYPE_SNIFF=1).
var noSniff = os.Getenv("GOSTORE_NO_CONTENT_TYPE_SNIFF") == "1"

// extraMimeTypes covers a few media types the stdlib mime table can miss on
// a minimal container image.
var extraMimeTypes = map[string]string{
	".mp4": "video/mp4", ".m4v": "video/mp4", ".mov": "video/quicktime",
	".webm": "video/webm", ".mkv": "video/x-matroska", ".avi": "video/x-msvideo",
	".mp3": "audio/mpeg", ".m4a": "audio/mp4", ".aac": "audio/aac",
	".flac": "audio/flac", ".wav": "audio/wav", ".ogg": "audio/ogg", ".oga": "audio/ogg",
	".webp": "image/webp", ".avif": "image/avif", ".svg": "image/svg+xml",
	".pdf": "application/pdf", ".json": "application/json", ".wasm": "application/wasm",
	".txt": "text/plain; charset=utf-8", ".csv": "text/csv; charset=utf-8",
	".md": "text/markdown; charset=utf-8",
}

// sniffContentType guesses a MIME type from the object key's extension.
func sniffContentType(key string) string {
	ext := strings.ToLower(path.Ext(key))
	if ext == "" {
		return ""
	}
	if v, ok := extraMimeTypes[ext]; ok {
		return v
	}
	return mime.TypeByExtension(ext)
}

// extractMetadata pulls content-type, content-encoding and x-amz-meta-* into
// the UserDefined map (keys lower-cased, x-amz-meta- prefix kept as-is on
// meta keys, plain "content-type"/"content-encoding" for those two).
//
// When the client sends no Content-Type, or the generic
// "application/octet-stream" (what curl and most SDKs default to), and the
// object key has a well-known extension, the type is filled in from that
// extension so the object plays / renders correctly when served later.
// applyDefaultEncryption turns on SSE-S3 for a write when the bucket has
// default encryption enabled and the caller didn't request encryption itself
// (S3 "default bucket encryption").
func (s *Server) applyDefaultEncryption(bucket string, ud map[string]string) {
	if s.bcfg == nil || ud == nil {
		return
	}
	if ud["x-amz-server-side-encryption"] != "" {
		return
	}
	if s.bcfg.Get(bucket).Encryption == "AES256" {
		ud["x-amz-server-side-encryption"] = "AES256"
	}
}

func extractMetadata(r *http.Request, key string) map[string]string {
	md := map[string]string{}
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if (ct == "" || ct == "application/octet-stream") && !noSniff {
		if guess := sniffContentType(key); guess != "" {
			ct = guess
		}
	}
	if ct != "" {
		md["content-type"] = ct
	}
	if v := r.Header.Get("Content-Encoding"); v != "" {
		md["content-encoding"] = v
	}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if len(vs) == 0 {
			continue
		}
		if strings.HasPrefix(lk, "x-amz-meta-") || lk == "x-amz-server-side-encryption" {
			md[lk] = vs[0]
		}
	}
	return md
}

func parseCopySource(v string) (bucket, key string, ok bool) {
	v = strings.TrimPrefix(v, "/")
	if i := strings.IndexByte(v, '?'); i >= 0 {
		v = v[:i] // strip ?versionId=...
	}
	if dec, err := url.QueryUnescape(v); err == nil {
		v = dec
	}
	i := strings.IndexByte(v, '/')
	if i <= 0 || i == len(v)-1 {
		return "", "", false
	}
	return v[:i], v[i+1:], true
}

// parseRange parses a single-range HTTP Range header into an HTTPRangeSpec.
func parseRange(v string) (*object.HTTPRangeSpec, bool) {
	if !strings.HasPrefix(v, "bytes=") {
		return nil, false
	}
	spec := strings.TrimPrefix(v, "bytes=")
	if strings.Contains(spec, ",") {
		return nil, false // multi-range unsupported
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return nil, false
	}
	startStr, endStr := spec[:dash], spec[dash+1:]
	switch {
	case startStr == "" && endStr == "":
		return nil, false
	case startStr == "":
		n, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || n <= 0 {
			return nil, false
		}
		return &object.HTTPRangeSpec{IsSuffixLength: true, Start: -n}, true
	default:
		start, err := strconv.ParseInt(startStr, 10, 64)
		if err != nil || start < 0 {
			return nil, false
		}
		end := int64(-1)
		if endStr != "" {
			end, err = strconv.ParseInt(endStr, 10, 64)
			if err != nil || end < start {
				return nil, false
			}
		}
		return &object.HTTPRangeSpec{Start: start, End: end}, true
	}
}

func resolveRangeForHeader(rs *object.HTTPRangeSpec, size int64) (start, length int64, ok bool) {
	if rs.IsSuffixLength {
		n := -rs.Start
		if n > size {
			n = size
		}
		return size - n, n, true
	}
	end := rs.End
	if end < 0 || end >= size {
		end = size - 1
	}
	return rs.Start, end - rs.Start + 1, true
}

// evalGetConditionals returns 0 to proceed, http.StatusNotModified, or
// http.StatusPreconditionFailed.
func evalGetConditionals(r *http.Request, oi object.ObjectInfo) int {
	etag := strings.Trim(oi.ETag, `"`)

	if inm := r.Header.Get("If-None-Match"); inm != "" {
		if inm == "*" || etagMatches(inm, etag) {
			return http.StatusNotModified
		}
	} else if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := http.ParseTime(ims); err == nil && !oi.ModTime.Truncate(time.Second).After(t) {
			return http.StatusNotModified
		}
	}

	if im := r.Header.Get("If-Match"); im != "" {
		if im != "*" && !etagMatches(im, etag) {
			return http.StatusPreconditionFailed
		}
	}
	if ius := r.Header.Get("If-Unmodified-Since"); ius != "" {
		if t, err := http.ParseTime(ius); err == nil && oi.ModTime.Truncate(time.Second).After(t) {
			return http.StatusPreconditionFailed
		}
	}
	return 0
}

func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		p := strings.TrimSpace(part)
		p = strings.TrimPrefix(p, "W/")
		p = strings.Trim(p, `"`)
		if p == etag {
			return true
		}
	}
	return false
}
