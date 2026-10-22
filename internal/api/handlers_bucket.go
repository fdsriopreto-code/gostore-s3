package api

import (
	"encoding/xml"
	"io"
	"net/http"
	"strconv"

	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/object"
)

func (s *Server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	// Body, if present, is a CreateBucketConfiguration with a LocationConstraint.
	loc := s.cfg.Region
	if r.ContentLength > 0 {
		var cbc struct {
			XMLName  xml.Name `xml:"CreateBucketConfiguration"`
			Location string   `xml:"LocationConstraint"`
		}
		if b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16)); len(b) > 0 {
			_ = xml.Unmarshal(b, &cbc)
			if cbc.Location != "" {
				loc = cbc.Location
			}
		}
	}
	lockEnabled := r.Header.Get("x-amz-bucket-object-lock-enabled") == "true"

	err := s.obj.MakeBucket(r.Context(), bucket, object.MakeBucketOptions{
		Location:    loc,
		LockEnabled: lockEnabled,
	})
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	if lockEnabled && s.bcfg != nil {
		_ = s.bcfg.Update(bucket, func(c *bucketcfg.Config) {
			c.ObjectLock = &bucketcfg.ObjectLockConfig{Enabled: true}
			c.Versioning = "Enabled"
		})
	}
	w.Header().Set("Location", "/"+bucket)
	writeSuccessOK(w)
}

func (s *Server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	if _, err := s.obj.GetBucketInfo(r.Context(), bucket); err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	w.Header().Set("x-amz-bucket-region", s.cfg.Region)
	writeSuccessOK(w)
}

func (s *Server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	force := r.Header.Get("x-amz-force-delete") == "true"
	err := s.obj.DeleteBucket(r.Context(), bucket, object.DeleteBucketOptions{Force: force})
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	if s.bcfg != nil {
		_ = s.bcfg.Delete(bucket)
	}
	s.ocache.evictBucket(bucket)
	writeSuccessNoContent(w)
}

func (s *Server) handleGetBucketLocation(w http.ResponseWriter, r *http.Request, bucket string) {
	if _, err := s.obj.GetBucketInfo(r.Context(), bucket); err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	loc := s.cfg.Region
	if loc == "us-east-1" {
		loc = "" // S3 quirk: us-east-1 is reported as an empty LocationConstraint
	}
	writeXML(w, http.StatusOK, locationConstraint{XMLNS: s3XMLNS, Location: loc})
}

type versioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	XMLNS   string   `xml:"xmlns,attr"`
	Status  string   `xml:"Status,omitempty"`
}

func (s *Server) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	if _, err := s.obj.GetBucketInfo(r.Context(), bucket); err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	st := ""
	if s.bcfg != nil {
		st = s.bcfg.Get(bucket).Versioning
	}
	writeXML(w, http.StatusOK, versioningConfiguration{XMLNS: s3XMLNS, Status: st})
}

func (s *Server) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	if _, err := s.obj.GetBucketInfo(r.Context(), bucket); err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var vc versioningConfiguration
	if err := xml.Unmarshal(b, &vc); err != nil {
		writeErrorResponse(w, r, ErrMalformedXML, "/"+bucket)
		return
	}
	if vc.Status != "Enabled" && vc.Status != "Suspended" {
		writeErrorResponse(w, r, ErrInvalidArgument, "/"+bucket)
		return
	}
	if err := s.bcfg.Update(bucket, func(c *bucketcfg.Config) { c.Versioning = vc.Status }); err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	writeSuccessOK(w)
}

func (s *Server) handleListObjectsV1(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	maxKeys := parseIntDefault(q.Get("max-keys"), 1000)
	prefix := q.Get("prefix")
	marker := q.Get("marker")
	delim := q.Get("delimiter")

	li, err := s.obj.ListObjects(r.Context(), bucket, prefix, marker, delim, maxKeys)
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	res := listBucketResult{
		XMLNS: s3XMLNS, Name: bucket, Prefix: prefix, Marker: marker,
		MaxKeys: maxKeys, Delimiter: delim,
		IsTruncated: li.IsTruncated, NextMarker: li.NextMarker,
	}
	for _, o := range li.Objects {
		res.Contents = append(res.Contents, toObjectXML(o))
	}
	for _, p := range li.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, commonPrefixXML{Prefix: p})
	}
	writeXML(w, http.StatusOK, res)
}

func (s *Server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	maxKeys := parseIntDefault(q.Get("max-keys"), 1000)
	prefix := q.Get("prefix")
	token := q.Get("continuation-token")
	startAfter := q.Get("start-after")
	delim := q.Get("delimiter")
	fetchOwner := q.Get("fetch-owner") == "true"

	li, err := s.obj.ListObjectsV2(r.Context(), bucket, prefix, token, delim, maxKeys, fetchOwner, startAfter)
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	res := listBucketV2Result{
		XMLNS: s3XMLNS, Name: bucket, Prefix: prefix, Delimiter: delim,
		MaxKeys: maxKeys, StartAfter: startAfter,
		ContinuationToken: token, NextContinuationToken: li.NextContinuationToken,
		IsTruncated: li.IsTruncated,
		KeyCount:    len(li.Objects) + len(li.Prefixes),
	}
	for _, o := range li.Objects {
		ox := toObjectXML(o)
		if fetchOwner {
			ox.Owner = &canonicalOwner{ID: "gostore", DisplayName: "gostore"}
		}
		res.Contents = append(res.Contents, ox)
	}
	for _, p := range li.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, commonPrefixXML{Prefix: p})
	}
	writeXML(w, http.StatusOK, res)
}

func (s *Server) handleListObjectVersions(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	maxKeys := parseIntDefault(q.Get("max-keys"), 1000)
	prefix := q.Get("prefix")
	delim := q.Get("delimiter")
	keyMarker := q.Get("key-marker")

	li, err := s.obj.ListObjectVersions(r.Context(), bucket, prefix, keyMarker, q.Get("version-id-marker"), delim, maxKeys)
	if err != nil {
		writeErrorResponse(w, r, toAPIError(err), "/"+bucket)
		return
	}
	type versionXML struct {
		XMLName      xml.Name `xml:"Version"`
		Key          string   `xml:"Key"`
		VersionID    string   `xml:"VersionId"`
		IsLatest     bool     `xml:"IsLatest"`
		LastModified string   `xml:"LastModified"`
		ETag         string   `xml:"ETag"`
		Size         int64    `xml:"Size"`
		StorageClass string   `xml:"StorageClass"`
	}
	type deleteMarkerXML struct {
		XMLName      xml.Name `xml:"DeleteMarker"`
		Key          string   `xml:"Key"`
		VersionID    string   `xml:"VersionId"`
		IsLatest     bool     `xml:"IsLatest"`
		LastModified string   `xml:"LastModified"`
	}
	type listVersionsResult struct {
		XMLName        xml.Name `xml:"ListVersionsResult"`
		XMLNS          string   `xml:"xmlns,attr"`
		Name           string   `xml:"Name"`
		Prefix         string   `xml:"Prefix"`
		KeyMarker      string   `xml:"KeyMarker"`
		MaxKeys        int      `xml:"MaxKeys"`
		Delimiter      string   `xml:"Delimiter,omitempty"`
		IsTruncated    bool     `xml:"IsTruncated"`
		Versions       []versionXML
		DeleteMarkers  []deleteMarkerXML
		CommonPrefixes []commonPrefixXML
	}
	res := listVersionsResult{
		XMLNS: s3XMLNS, Name: bucket, Prefix: prefix, KeyMarker: keyMarker,
		MaxKeys: maxKeys, Delimiter: delim, IsTruncated: li.IsTruncated,
	}
	for _, o := range li.Objects {
		vid := o.VersionID
		if vid == "" {
			vid = "null"
		}
		if o.DeleteMarker {
			res.DeleteMarkers = append(res.DeleteMarkers, deleteMarkerXML{
				Key: o.Name, VersionID: vid, IsLatest: o.IsLatest, LastModified: amzTime(o.ModTime),
			})
			continue
		}
		res.Versions = append(res.Versions, versionXML{
			Key: o.Name, VersionID: vid, IsLatest: o.IsLatest,
			LastModified: amzTime(o.ModTime), ETag: quoteETag(o.ETag),
			Size: o.Size, StorageClass: "STANDARD",
		})
	}
	for _, p := range li.Prefixes {
		res.CommonPrefixes = append(res.CommonPrefixes, commonPrefixXML{Prefix: p})
	}
	writeXML(w, http.StatusOK, res)
}

func (s *Server) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErrorResponse(w, r, ErrInternalError, "/"+bucket)
		return
	}
	var req deleteRequest
	if err := xml.Unmarshal(b, &req); err != nil {
		writeErrorResponse(w, r, ErrMalformedXML, "/"+bucket)
		return
	}
	// errs is indexed by the original request order. Keys that would escape
	// the bucket (../, leading /) or reach the reserved system namespace are
	// rejected here and never reach the backend; the valid remainder is
	// deleted in one batch and its results scattered back into place.
	errs := make([]error, len(req.Objects))
	var valid []object.ObjectToDelete
	var validIdx []int
	for i, o := range req.Objects {
		if !validObjectKey(o.Key) {
			errs[i] = object.ErrObjectNameInvalid
			continue
		}
		validIdx = append(validIdx, i)
		valid = append(valid, object.ObjectToDelete{ObjectName: o.Key, VersionID: o.VersionID})
	}
	if len(valid) > 0 {
		_, derrs := s.obj.DeleteObjects(r.Context(), bucket, valid, object.ObjectOptions{})
		for j, orig := range validIdx {
			errs[orig] = derrs[j]
		}
	}

	res := deleteResult{XMLNS: s3XMLNS}
	for i, o := range req.Objects {
		if errs[i] != nil {
			ae := GetAPIError(toAPIError(errs[i]))
			res.Errors = append(res.Errors, deleteErrorXML{Key: o.Key, Code: ae.Code, Message: ae.Description})
			continue
		}
		s.ocache.evict(bucket, o.Key, "")
		if !req.Quiet {
			res.Deleted = append(res.Deleted, deletedXML{Key: o.Key})
		}
	}
	writeXML(w, http.StatusOK, res)
}

// --- helpers -------------------------------------------------------------

func toObjectXML(o object.ObjectInfo) objectXML {
	sc := o.StorageClass
	if sc == "" {
		sc = "STANDARD"
	}
	return objectXML{
		Key:          o.Name,
		LastModified: amzTime(o.ModTime),
		ETag:         quoteETag(o.ETag),
		Size:         o.Size,
		StorageClass: sc,
	}
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}
