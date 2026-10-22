package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/config"
	"github.com/lojadopocket/gostore/internal/console"
	"github.com/lojadopocket/gostore/internal/event"
	"github.com/lojadopocket/gostore/internal/iam"
	"github.com/lojadopocket/gostore/internal/object"
	"github.com/lojadopocket/gostore/internal/replication"
	"github.com/lojadopocket/gostore/internal/scanner"
)

// Server is the S3 + admin API HTTP handler.
type Server struct {
	cfg  config.Config
	obj  object.Layer
	iam  *iam.Manager
	bcfg *bucketcfg.Store
	bus  *event.Bus
	repl *replication.Manager
	scan *scanner.Scanner
	rl   *rateLimiter

	polCache *bucketPolicyCache
	ocache   *objCache
	ro       readOnlyState
	adm      *admissionControl
	backup   *backupJob

	domainNames []string

	// copySrcAuthz controls the CopyObject/UploadPartCopy source-read check:
	//   "enforce" (default) — deny a copy whose caller cannot read the source;
	//   "warn"              — allow it but log a warning (safe rollout on an
	//                         existing deployment: observe, fix policies, then
	//                         switch to enforce);
	//   "off"               — skip the check entirely (not recommended).
	copySrcAuthz string
}

type ctxKeyAccessKey struct{}

// NewServer builds the S3 API handler. clusterRPC, when non-nil, is mounted
// at /gostore/internal/ for inter-node disk + lock RPC.
func NewServer(cfg config.Config, obj object.Layer, im *iam.Manager, bc *bucketcfg.Store, bus *event.Bus, clusterRPC http.Handler, scan *scanner.Scanner) http.Handler {
	if scan == nil {
		scan = scanner.New(obj, bc, 0)
	}
	s := &Server{
		cfg: cfg, obj: obj, iam: im, bcfg: bc, bus: bus,
		repl:     replication.New(bc, obj),
		scan:     scan,
		rl:       newRateLimiter(),
		polCache: newBucketPolicyCache(),
		ocache:   newObjCache(),
		adm:      newAdmissionControl(),
	}
	vol0 := ""
	if len(cfg.Volumes) > 0 {
		vol0 = cfg.Volumes[0]
	}
	auditL = newAuditLog(vol0)
	s.backup = newBackupJob(obj)
	go s.watchQuorum(context.Background())
	go s.backup.loop(context.Background())
	go s.repl.StartWorker(context.Background())
	if v := strings.TrimSpace(os.Getenv("GOSTORE_DOMAIN")); v != "" {
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				s.domainNames = append(s.domainNames, d)
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GOSTORE_COPY_SOURCE_AUTHZ"))) {
	case "warn":
		s.copySrcAuthz = "warn"
	case "off":
		s.copySrcAuthz = "off"
	default:
		s.copySrcAuthz = "enforce"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /gostore/health/live", s.handleHealthLive)
	mux.HandleFunc("GET /gostore/health/ready", s.handleHealthReady)
	mux.HandleFunc("GET /gostore/health/cluster", s.handleHealthReady)
	mux.HandleFunc("GET /gostore/health/selftest", s.handleSelfTest)
	mux.HandleFunc("GET /gostore/health/persistence", s.handlePersistence)
	mux.HandleFunc("GET /gostore/metrics", s.handleMetrics)
	mux.Handle("/gostore/admin/v1/", http.HandlerFunc(s.handleAdmin))
	mux.Handle("/gostore/ingest/", http.HandlerFunc(s.handleIngest))
	if clusterRPC != nil {
		mux.Handle("/gostore/internal/", clusterRPC)
	}
	mux.Handle("/gostore/console/", http.StripPrefix("/gostore/console", console.Handler()))
	mux.HandleFunc("/gostore/console", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/gostore/console/", http.StatusFound)
	})
	mux.Handle("/", http.HandlerFunc(s.handleS3))

	return chain(mux,
		withRequestID,
		withRecover,
		withAccessLog,
		withBodyIdleTimeout,
	)
}

type s3Request struct {
	Bucket string
	Object string
	Style  string
}

func (s *Server) parseRequest(r *http.Request) s3Request {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, d := range s.domainNames {
		if host == d {
			break
		}
		if strings.HasSuffix(host, "."+d) {
			return s3Request{
				Bucket: strings.TrimSuffix(host, "."+d),
				Object: strings.TrimPrefix(r.URL.Path, "/"),
				Style:  "vhost",
			}
		}
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		return s3Request{Style: "path"}
	}
	if i := strings.IndexByte(p, '/'); i >= 0 {
		return s3Request{Bucket: p[:i], Object: p[i+1:], Style: "path"}
	}
	return s3Request{Bucket: p, Style: "path"}
}

// handleS3 authenticates, authorizes, then dispatches to the operation handler.
func (s *Server) handleS3(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w, s.cfg.Region)

	// Friendly landing: a plain browser navigation to the root (GET /, no S3
	// credentials, no query, Accept: text/html) is sent to the web console
	// instead of the SigV4 "AccessDenied" XML an S3 client would expect. S3
	// SDKs send an Authorization header (or presign query) and don't ask for
	// text/html, so they fall through to the normal API untouched.
	if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.RawQuery == "" &&
		r.Header.Get("Authorization") == "" &&
		strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/gostore/console/", http.StatusFound)
		return
	}

	req := s.parseRequest(r)

	newBody, accessKey, errCode := s.authenticate(r)
	if errCode != ErrNone {
		writeErrorResponse(w, r, errCode, r.URL.Path)
		return
	}
	if newBody != nil {
		r.Body = newBody
	}
	r = r.WithContext(context.WithValue(r.Context(), ctxKeyAccessKey{}, accessKey))
	if sr, ok := w.(*statusRecorder); ok {
		sr.accessKey = accessKey
		sr.authAt = time.Now()
	}

	if s.rl != nil {
		rlKey := accessKey
		if rlKey == "" {
			rlKey = "anon:" + clientIP(r)
		}
		if !s.rl.allow(rlKey) {
			w.Header().Set("Retry-After", "1")
			writeErrorResponse(w, r, ErrSlowDown, r.URL.Path)
			return
		}
	}

	// STS AssumeRole is allowed for any authenticated caller, ahead of authz.
	if req.Bucket == "" && isSTSRequest(r) {
		s.handleAssumeRole(w, r, accessKey)
		return
	}

	// Browser POST-form upload authenticates via its own signed policy, not
	// the Authorization header — handle it before the normal authz path.
	if isPostFormUpload(r, req) {
		s.handlePostObjectForm(w, r, req.Bucket)
		return
	}

	q := r.URL.Query()

	// Write admission: read-only mode + global in-flight-bytes / memory shed.
	if isMutatingRequest(r, q) {
		if s.ro.on() {
			w.Header().Set("Retry-After", "10")
			writeErrorResponse(w, r, ErrServerReadOnly, r.URL.Path)
			return
		}
		if rel, ok := s.adm.admit(admissionBytes(r)); ok {
			defer rel()
		} else {
			w.Header().Set("Retry-After", "1")
			writeErrorResponse(w, r, ErrBusy, r.URL.Path)
			return
		}
	}

	// Static-website serving: a plain GET (no S3 sub-resource query) against a
	// website-enabled bucket serves index/error documents. Sub-resource calls
	// (?list-type, ?versioning, ?w=, …) fall through to the normal API.
	if r.Method == http.MethodGet {
		if ws := s.websiteConfigFor(req.Bucket, q); ws != nil {
			s.serveWebsite(w, r, req.Bucket, req.Object, ws, accessKey)
			return
		}
	}

	// CORS: answer preflight, and stamp headers on the eventual response.
	if s.applyCORS(w, r, req.Bucket) {
		return
	}

	if sr, ok := w.(*statusRecorder); ok {
		sr.s3action = s3Action(r, req, q)
	}

	if code := s.authorizeS3(r, req, q, accessKey); code != ErrNone {
		writeErrorResponse(w, r, code, r.URL.Path)
		return
	}

	switch {
	case req.Bucket == "":
		if r.Method == http.MethodGet {
			s.handleListBuckets(w, r)
			return
		}
		writeErrorResponse(w, r, ErrMethodNotAllowed, "/")

	case req.Object == "":
		s.dispatchBucket(w, r, req.Bucket, q)

	default:
		s.dispatchObject(w, r, req.Bucket, req.Object, q)
	}
}

func (s *Server) dispatchBucket(w http.ResponseWriter, r *http.Request, bucket string, q map[string][]string) {
	has := func(k string) bool { _, ok := q[k]; return ok }
	switch r.Method {
	case http.MethodGet:
		switch {
		case has("location"):
			s.handleGetBucketLocation(w, r, bucket)
		case has("uploads"):
			s.handleListMultipartUploads(w, r, bucket)
		case has("versioning"):
			s.handleGetBucketVersioning(w, r, bucket)
		case has("versions"):
			s.handleListObjectVersions(w, r, bucket)
		case has("policy"):
			s.handleGetBucketPolicy(w, r, bucket)
		case has("tagging"):
			s.handleGetBucketTagging(w, r, bucket)
		case has("cors"):
			s.handleGetBucketCORS(w, r, bucket)
		case has("object-lock"):
			s.handleGetBucketObjectLock(w, r, bucket)
		case has("replication"):
			s.handleGetBucketReplication(w, r, bucket)
		case has("lifecycle"):
			s.handleGetBucketLifecycle(w, r, bucket)
		case has("notification"):
			s.handleGetBucketNotification(w, r, bucket)
		case has("website"):
			s.handleGetBucketWebsite(w, r, bucket)
		case has("compression"):
			s.handleGetBucketCompression(w, r, bucket)
		case has("quota"):
			s.handleGetBucketQuota(w, r, bucket)
		case q["list-type"] != nil && q["list-type"][0] == "2":
			s.handleListObjectsV2(w, r, bucket)
		default:
			s.handleListObjectsV1(w, r, bucket)
		}
	case http.MethodPut:
		switch {
		case has("policy"):
			s.handlePutBucketPolicy(w, r, bucket)
		case has("tagging"):
			s.handlePutBucketTagging(w, r, bucket)
		case has("cors"):
			s.handlePutBucketCORS(w, r, bucket)
		case has("notification"):
			s.handlePutBucketNotification(w, r, bucket)
		case has("versioning"):
			s.handlePutBucketVersioning(w, r, bucket)
		case has("object-lock"):
			s.handlePutBucketObjectLock(w, r, bucket)
		case has("replication"):
			s.handlePutBucketReplication(w, r, bucket)
		case has("lifecycle"):
			s.handlePutBucketLifecycle(w, r, bucket)
		case has("website"):
			s.handlePutBucketWebsite(w, r, bucket)
		case has("compression"):
			s.handlePutBucketCompression(w, r, bucket)
		case has("quota"):
			s.handlePutBucketQuota(w, r, bucket)
		case has("acl"):
			writeSuccessOK(w) // accept-and-ignore
		default:
			s.handleCreateBucket(w, r, bucket)
		}
	case http.MethodDelete:
		switch {
		case has("policy"):
			s.handleDeleteBucketPolicy(w, r, bucket)
		case has("tagging"):
			s.handleDeleteBucketTagging(w, r, bucket)
		case has("cors"):
			s.handleDeleteBucketCORS(w, r, bucket)
		case has("replication"):
			s.handleDeleteBucketReplication(w, r, bucket)
		case has("lifecycle"):
			s.handleDeleteBucketLifecycle(w, r, bucket)
		case has("website"):
			s.handleDeleteBucketWebsite(w, r, bucket)
		case has("quota"):
			s.handleDeleteBucketQuota(w, r, bucket)
		default:
			s.handleDeleteBucket(w, r, bucket)
		}
	case http.MethodHead:
		s.handleHeadBucket(w, r, bucket)
	case http.MethodPost:
		if has("delete") {
			s.handleDeleteObjects(w, r, bucket)
			return
		}
		writeErrorResponse(w, r, ErrMethodNotAllowed, "/"+bucket)
	default:
		writeErrorResponse(w, r, ErrMethodNotAllowed, "/"+bucket)
	}
}

func (s *Server) dispatchObject(w http.ResponseWriter, r *http.Request, bucket, object string, q map[string][]string) {
	has := func(k string) bool { _, ok := q[k]; return ok }
	res := "/" + bucket + "/" + object
	switch r.Method {
	case http.MethodGet:
		if has("uploadId") {
			s.handleListObjectParts(w, r, bucket, object)
			return
		}
		if has("preview") || has("img") || has("w") || has("h") {
			s.handleObjectPreview(w, r, bucket, object)
			return
		}
		if has("tagging") {
			s.handleGetObjectTagging(w, r, bucket, object)
			return
		}
		if has("retention") {
			s.handleGetObjectRetention(w, r, bucket, object)
			return
		}
		if has("legal-hold") {
			s.handleGetObjectLegalHold(w, r, bucket, object)
			return
		}
		if has("acl") {
			writeErrorResponse(w, r, ErrNotImplemented, res)
			return
		}
		s.handleGetObject(w, r, bucket, object)
	case http.MethodHead:
		s.handleHeadObject(w, r, bucket, object)
	case http.MethodPut:
		if has("uploadId") && has("partNumber") {
			if r.Header.Get("x-amz-copy-source") != "" {
				s.handleCopyObjectPart(w, r, bucket, object)
			} else {
				s.handlePutObjectPart(w, r, bucket, object)
			}
			return
		}
		if r.Header.Get("x-amz-copy-source") != "" {
			s.handleCopyObject(w, r, bucket, object)
			return
		}
		if has("tagging") {
			s.handlePutObjectTagging(w, r, bucket, object)
			return
		}
		if has("retention") {
			s.handlePutObjectRetention(w, r, bucket, object)
			return
		}
		if has("legal-hold") {
			s.handlePutObjectLegalHold(w, r, bucket, object)
			return
		}
		if has("acl") {
			writeSuccessOK(w)
			return
		}
		s.handlePutObject(w, r, bucket, object)
	case http.MethodPost:
		if has("uploads") {
			s.handleNewMultipartUpload(w, r, bucket, object)
			return
		}
		if has("uploadId") {
			s.handleCompleteMultipartUpload(w, r, bucket, object)
			return
		}
		writeErrorResponse(w, r, ErrMethodNotAllowed, res)
	case http.MethodDelete:
		if has("uploadId") {
			s.handleAbortMultipartUpload(w, r, bucket, object)
			return
		}
		if has("tagging") {
			s.handleDeleteObjectTagging(w, r, bucket, object)
			return
		}
		s.handleDeleteObject(w, r, bucket, object)
	default:
		writeErrorResponse(w, r, ErrMethodNotAllowed, res)
	}
}
