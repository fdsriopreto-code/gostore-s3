package api

import (
	"encoding/xml"
	"io"
	"net/http"
	"strconv"

	"github.com/lojadopocket/gostore/internal/event"
	"github.com/lojadopocket/gostore/internal/object"
)

func (s *Server) handleNewMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	opts := object.ObjectOptions{UserDefined: extractMetadata(r, key)}
	if v := r.Header.Get("x-amz-tagging"); v != "" {
		opts.UserTags = v
	}
	res, err := s.obj.NewMultipartUpload(r.Context(), bucket, key, opts)
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	writeXML(w, http.StatusOK, initiateMultipartUploadResult{
		XMLNS: s3XMLNS, Bucket: bucket, Key: key, UploadID: res.UploadID,
	})
}

func (s *Server) handlePutObjectPart(w http.ResponseWriter, r *http.Request, bucket, key string) {
	q := r.URL.Query()
	uploadID := q.Get("uploadId")
	partNum, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || partNum < 1 || partNum > 10000 {
		writeErrorResponse(w, r, ErrInvalidPart, "/"+bucket+"/"+key)
		return
	}
	size := bodySize(r)
	if size < 0 {
		writeErrorResponse(w, r, ErrMissingContentLength, "/"+bucket+"/"+key)
		return
	}
	if s.quotaExceeded(bucket, size) {
		writeErrorResponse(w, r, ErrQuotaExceeded, "/"+bucket+"/"+key)
		return
	}
	pi, err := s.obj.PutObjectPart(r.Context(), bucket, key, uploadID, partNum,
		object.NewPutObjReader(r.Body, size, size), object.ObjectOptions{})
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	w.Header().Set("ETag", quoteETag(pi.ETag))
	writeSuccessOK(w)
}

func (s *Server) handleCopyObjectPart(w http.ResponseWriter, r *http.Request, bucket, key string) {
	q := r.URL.Query()
	uploadID := q.Get("uploadId")
	partNum, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || partNum < 1 || partNum > 10000 {
		writeErrorResponse(w, r, ErrInvalidPart, "/"+bucket+"/"+key)
		return
	}
	srcBucket, srcKey, ok := parseCopySource(r.Header.Get("x-amz-copy-source"))
	if !ok || !validBucket(srcBucket) || !validObjectKey(srcKey) || !validObjectKey(key) {
		writeErrorResponse(w, r, ErrInvalidArgument, "/"+bucket+"/"+key)
		return
	}
	if code := s.authorizeCopySource(r, accessKeyFrom(r), srcBucket, srcKey); code != ErrNone {
		writeErrorResponse(w, r, code, "/"+srcBucket+"/"+srcKey)
		return
	}
	var startOff, length int64 = 0, -1
	if rh := r.Header.Get("x-amz-copy-source-range"); rh != "" {
		if spec, ok := parseRange(rh); ok {
			srcInfo, ierr := s.obj.GetObjectInfo(r.Context(), srcBucket, srcKey, object.ObjectOptions{})
			if ierr != nil {
				writeErrorResponse(w, r, toAPIError(ierr), "/"+srcBucket+"/"+srcKey)
				return
			}
			startOff, length, _ = resolveRangeForHeader(spec, srcInfo.Size)
		}
	}
	pi, err := s.obj.CopyObjectPart(r.Context(), srcBucket, srcKey, bucket, key, uploadID, partNum,
		startOff, length, object.ObjectInfo{}, object.ObjectOptions{}, object.ObjectOptions{})
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	writeXML(w, http.StatusOK, copyPartResult{
		XMLNS: s3XMLNS, LastModified: amzTime(pi.LastModified), ETag: quoteETag(pi.ETag),
	})
}

func (s *Server) handleListObjectParts(w http.ResponseWriter, r *http.Request, bucket, key string) {
	q := r.URL.Query()
	uploadID := q.Get("uploadId")
	marker, _ := strconv.Atoi(q.Get("part-number-marker"))
	maxParts := parseIntDefault(q.Get("max-parts"), 1000)

	res, err := s.obj.ListObjectParts(r.Context(), bucket, key, uploadID, marker, maxParts, object.ObjectOptions{})
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	out := listPartsResult{
		XMLNS: s3XMLNS, Bucket: bucket, Key: key, UploadID: uploadID,
		StorageClass: "STANDARD", PartNumberMarker: marker,
		NextPartNumberMarker: res.NextPartNumberMarker, MaxParts: maxParts,
		IsTruncated: res.IsTruncated,
		Owner:       canonicalOwner{ID: "gostore", DisplayName: "gostore"},
		Initiator:   canonicalOwner{ID: "gostore", DisplayName: "gostore"},
	}
	for _, p := range res.Parts {
		out.Parts = append(out.Parts, partXML{
			PartNumber: p.PartNumber, LastModified: amzTime(p.LastModified),
			ETag: quoteETag(p.ETag), Size: p.Size,
		})
	}
	writeXML(w, http.StatusOK, out)
}

func (s *Server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	maxUploads := parseIntDefault(q.Get("max-uploads"), 1000)
	res, err := s.obj.ListMultipartUploads(r.Context(), bucket, q.Get("prefix"),
		q.Get("key-marker"), q.Get("upload-id-marker"), q.Get("delimiter"), maxUploads)
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	out := listMultipartUploadsResult{
		XMLNS: s3XMLNS, Bucket: bucket, MaxUploads: maxUploads,
		KeyMarker: q.Get("key-marker"), UploadIDMarker: q.Get("upload-id-marker"),
		NextKeyMarker: res.NextKeyMarker, NextUploadIDMarker: res.NextUploadIDMarker,
		IsTruncated: res.IsTruncated,
	}
	for _, u := range res.Uploads {
		out.Uploads = append(out.Uploads, uploadXML{
			Key: u.Object, UploadID: u.UploadID,
			Initiated: amzTime(u.Initiated), StorageClass: "STANDARD",
		})
	}
	writeXML(w, http.StatusOK, out)
}

func (s *Server) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	uploadID := r.URL.Query().Get("uploadId")
	if err := s.obj.AbortMultipartUpload(r.Context(), bucket, key, uploadID, object.ObjectOptions{}); err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	writeSuccessNoContent(w)
}

func (s *Server) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, key string) {
	uploadID := r.URL.Query().Get("uploadId")
	b, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket+"/"+key)
		return
	}
	var req completeMultipartUpload
	if err := xml.Unmarshal(b, &req); err != nil || len(req.Parts) == 0 {
		writeErrorResponse(w, r, ErrMalformedXML, "/"+bucket+"/"+key)
		return
	}
	parts := make([]object.CompletePart, len(req.Parts))
	for i, p := range req.Parts {
		parts[i] = object.CompletePart{PartNumber: p.PartNumber, ETag: p.ETag}
	}
	oi, err := s.obj.CompleteMultipartUpload(r.Context(), bucket, key, uploadID, parts, object.ObjectOptions{})
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket+"/"+key)
		return
	}
	s.notify(r, event.ObjectCreated, bucket, key, oi.Size, oi.ETag)
	// S3 streams whitespace while assembling; we just return the result.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	writeXML(w, http.StatusOK, completeMultipartUploadResult{
		XMLNS:    s3XMLNS,
		Location: scheme + "://" + r.Host + "/" + bucket + "/" + key,
		Bucket:   bucket, Key: key, ETag: quoteETag(oi.ETag),
	})
}
