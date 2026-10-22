package api

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"

	"github.com/lojadopocket/gostore/internal/bucketcfg"
)

type bucketQuota struct {
	Bytes   int64 `json:"bytes"`
	Objects int64 `json:"objects"`
}

// quotaExceeded reports whether writing addBytes (and one more object) to the
// bucket would push it past its configured quota. It uses the scanner's last
// usage snapshot, so it's a soft limit — a burst of concurrent writes can
// briefly overshoot before the next scan.
func (s *Server) quotaExceeded(bucket string, addBytes int64) bool {
	c := s.bcfg.Get(bucket)
	if c.QuotaBytes <= 0 && c.QuotaObjects <= 0 {
		return false
	}
	u := s.scan.Usage()
	if u == nil {
		return false
	}
	bu := u.Buckets[bucket]
	if c.QuotaBytes > 0 && bu.Bytes+addBytes > c.QuotaBytes {
		return true
	}
	if c.QuotaObjects > 0 && bu.Objects+1 > c.QuotaObjects {
		return true
	}
	return false
}

// GET /{bucket}?quota
func (s *Server) handleGetBucketQuota(w http.ResponseWriter, r *http.Request, bucket string) {
	c := s.bcfg.Get(bucket)
	writeJSON(w, http.StatusOK, bucketQuota{Bytes: c.QuotaBytes, Objects: c.QuotaObjects})
}

// PUT /{bucket}?quota  body: {"bytes":N,"objects":M}
func (s *Server) handlePutBucketQuota(w http.ResponseWriter, r *http.Request, bucket string) {
	var q bucketQuota
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&q); err != nil {
		writeErrorResponse(w, r, ErrMalformedXML, "/"+bucket)
		return
	}
	if q.Bytes < 0 || q.Objects < 0 {
		writeErrorResponse(w, r, ErrInvalidArgument, "/"+bucket)
		return
	}
	if err := s.bcfg.Update(bucket, func(c *bucketcfg.Config) {
		c.QuotaBytes = q.Bytes
		c.QuotaObjects = q.Objects
	}); err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	writeSuccessOK(w)
}

// DELETE /{bucket}?quota
func (s *Server) handleDeleteBucketQuota(w http.ResponseWriter, r *http.Request, bucket string) {
	if err := s.bcfg.Update(bucket, func(c *bucketcfg.Config) {
		c.QuotaBytes, c.QuotaObjects = 0, 0
	}); err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	writeSuccessNoContent(w)
}

// --- ?compression (gostore-native bucket toggle) ----------------------

// GET /{bucket}?compression
func (s *Server) handleGetBucketCompression(w http.ResponseWriter, r *http.Request, bucket string) {
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": s.bcfg.Get(bucket).Compress})
}

// PUT /{bucket}?compression  body: {"enabled":true}
func (s *Server) handlePutBucketCompression(w http.ResponseWriter, r *http.Request, bucket string) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeErrorResponse(w, r, ErrMalformedXML, "/"+bucket)
		return
	}
	if err := s.bcfg.Update(bucket, func(c *bucketcfg.Config) { c.Compress = body.Enabled }); err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	writeSuccessOK(w)
}

// --- default bucket encryption (?encryption) ---------------------------

type sseConfigXML struct {
	XMLName xml.Name `xml:"ServerSideEncryptionConfiguration"`
	Rules   []struct {
		Default struct {
			Algorithm string `xml:"SSEAlgorithm"`
		} `xml:"ApplyServerSideEncryptionByDefault"`
	} `xml:"Rule"`
}

type sseConfigOut struct {
	XMLName xml.Name `xml:"ServerSideEncryptionConfiguration"`
	XMLNS   string   `xml:"xmlns,attr"`
	Rule    struct {
		Default struct {
			Algorithm string `xml:"SSEAlgorithm"`
		} `xml:"ApplyServerSideEncryptionByDefault"`
	} `xml:"Rule"`
}

func (s *Server) handleGetBucketEncryption(w http.ResponseWriter, r *http.Request, bucket string) {
	enc := s.bcfg.Get(bucket).Encryption
	if enc == "" {
		writeErrorResponse(w, r, ErrNoSuchEncryptionConfiguration, "/"+bucket)
		return
	}
	var out sseConfigOut
	out.XMLNS = s3XMLNS
	out.Rule.Default.Algorithm = enc
	writeXML(w, http.StatusOK, out)
}

func (s *Server) handlePutBucketEncryption(w http.ResponseWriter, r *http.Request, bucket string) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	var cfg sseConfigXML
	if err := xml.Unmarshal(b, &cfg); err != nil || len(cfg.Rules) == 0 {
		writeErrorResponse(w, r, ErrMalformedXML, "/"+bucket)
		return
	}
	alg := cfg.Rules[0].Default.Algorithm
	if alg != "AES256" {
		// Only SSE-S3 (AES256) is supported as a default; aws:kms etc. are not.
		writeErrorResponse(w, r, ErrInvalidArgument, "/"+bucket)
		return
	}
	if err := s.bcfg.Update(bucket, func(c *bucketcfg.Config) { c.Encryption = alg }); err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	writeSuccessOK(w)
}

func (s *Server) handleDeleteBucketEncryption(w http.ResponseWriter, r *http.Request, bucket string) {
	if err := s.bcfg.Update(bucket, func(c *bucketcfg.Config) { c.Encryption = "" }); err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
