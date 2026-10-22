package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/lojadopocket/gostore/internal/cluster"
	"github.com/lojadopocket/gostore/internal/erasure"
	"github.com/lojadopocket/gostore/internal/iam"
	"github.com/lojadopocket/gostore/internal/iam/policy"
	"github.com/lojadopocket/gostore/internal/metrics"
	"github.com/lojadopocket/gostore/internal/object"
	"github.com/lojadopocket/gostore/internal/storage"
)

// handleAdmin serves the gostore-native admin API under /gostore/admin/v1/.
// Every route requires SigV4 auth plus an "admin:*" permission (the
// consoleAdmin builtin policy, or root).
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w, s.cfg.Region)

	newBody, accessKey, code := s.authenticate(r)
	if code != ErrNone {
		writeJSONError(w, http.StatusForbidden, "authentication failed")
		return
	}
	if newBody != nil {
		r.Body = newBody
	}
	path := strings.TrimPrefix(r.URL.Path, "/gostore/admin/v1/")
	q := r.URL.Query()

	isAdmin := accessKey != "" && s.iam.IsAllowed(accessKey, policy.Args{Action: "admin:*", BucketName: "*"})

	// whoami is available to any authenticated caller (not just admins) so a
	// key can inspect its own identity and effective policies.
	if path == "whoami" && r.Method == http.MethodGet {
		s.adminWhoami(w, accessKey, isAdmin)
		return
	}
	if !isAdmin {
		writeJSONError(w, http.StatusForbidden, "admin permission required")
		return
	}

	switch {
	case path == "info" && r.Method == http.MethodGet:
		s.adminInfo(w, r)
	case path == "metrics" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, metrics.Snap())
	case path == "heal" && r.Method == http.MethodPost:
		s.adminHeal(w, r)
	case path == "scanner/run" && r.Method == http.MethodPost:
		writeJSON(w, http.StatusOK, s.scan.ScanOnce(r.Context()))
	case path == "scrub" && r.Method == http.MethodGet:
		st := s.scan.ScrubStatus()
		if st == nil {
			writeJSON(w, http.StatusOK, map[string]any{"running": false, "neverRun": true})
			return
		}
		writeJSON(w, http.StatusOK, st)
	case path == "scrub" && r.Method == http.MethodPost:
		go s.scan.DeepScrub(context.Background())
		writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
	case path == "readonly":
		s.handleAdminReadOnly(w, r)
	case path == "snapshot" && r.Method == http.MethodPost:
		s.adminSnapshotCreate(w, r)
	case path == "snapshot" && r.Method == http.MethodDelete:
		s.adminSnapshotDelete(w, r)
	case path == "snapshots" && r.Method == http.MethodGet:
		s.adminSnapshotList(w, r)
	case path == "snapshot/restore" && r.Method == http.MethodPost:
		s.adminSnapshotRestore(w, r)
	case path == "audit" && r.Method == http.MethodGet:
		s.handleAdminAudit(w, r)
	case path == "audit/verify" && r.Method == http.MethodGet:
		s.handleAdminAuditVerify(w, r)
	case path == "cluster" && r.Method == http.MethodGet:
		peers := cluster.PeerHealth()
		up := 0
		for _, p := range peers {
			if p.Up {
				up++
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"peers": peers, "peersUp": up, "peersTotal": len(peers),
			"health": s.obj.Health(r.Context(), object.HealthOptions{}),
		})
	case path == "du" && r.Method == http.MethodGet:
		bucket := r.URL.Query().Get("bucket")
		prefix := r.URL.Query().Get("prefix")
		self, children := s.scan.PrefixUsage(bucket, prefix)
		writeJSON(w, http.StatusOK, map[string]any{
			"bucket": bucket, "prefix": prefix,
			"self": self, "folders": children,
			"asOf": func() any {
				if u := s.scan.Usage(); u != nil {
					return u.LastUpdate
				}
				return nil
			}(),
		})
	case path == "datausage" && r.Method == http.MethodGet:
		u := s.scan.Usage()
		if u == nil {
			writeJSON(w, http.StatusOK, map[string]any{"pending": true})
			return
		}
		writeJSON(w, http.StatusOK, u)
	case path == "activity" && r.Method == http.MethodGet:
		s.handleActivity(w, r)
	case path == "users/rotate-secret" && r.Method == http.MethodPost:
		s.adminRotateSecret(w, r)
	case path == "buckets/empty" && r.Method == http.MethodPost:
		s.adminEmptyBucket(w, r)
	case path == "ingest-keys" && r.Method == http.MethodGet:
		s.adminIngestKeysList(w, r)
	case path == "ingest-keys" && r.Method == http.MethodPost:
		s.adminIngestKeyCreate(w, r)
	case path == "ingest-keys" && r.Method == http.MethodDelete:
		s.adminIngestKeyDelete(w, r)
	case path == "backup":
		s.handleAdminBackup(w, r)
	case path == "backup/run" && r.Method == http.MethodPost:
		s.handleAdminBackupRun(w, r)
	case path == "backup/restore" && r.Method == http.MethodPost:
		s.handleAdminBackupRestore(w, r)
	case path == "backup/verify" && r.Method == http.MethodPost:
		s.handleAdminBackupVerify(w, r)
	case path == "replication/backfill" && r.Method == http.MethodPost:
		s.handleAdminReplicationBackfill(w, r)
	case path == "replication" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"pending": s.repl.Pending()})
	case path == "pool" && r.Method == http.MethodGet:
		s.adminPoolStatus(w)
	case path == "pool/decommission" && r.Method == http.MethodPost:
		s.adminPoolDecommission(w, r)
	case path == "pool/rebalance" && r.Method == http.MethodPost:
		s.adminPoolRebalance(w)
	case path == "users" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.iam.ListUsers())
	case path == "users" && r.Method == http.MethodPut:
		s.adminAddUser(w, r)
	case path == "users" && r.Method == http.MethodDelete:
		if err := s.iam.RemoveUser(q.Get("accessKey")); err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case path == "users/status" && r.Method == http.MethodPost:
		var body struct{ AccessKey, Status string }
		if !decodeJSON(w, r, &body) {
			return
		}
		if err := s.iam.SetUserStatus(body.AccessKey, body.Status); err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
	case path == "policies" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.iam.ListPolicies())
	case path == "policies" && r.Method == http.MethodPut:
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err := s.iam.SetPolicy(q.Get("name"), b); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusOK)
	case path == "policies" && r.Method == http.MethodDelete:
		if err := s.iam.RemovePolicy(q.Get("name")); err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case path == "service-accounts" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, s.iam.ListServiceAccounts(q.Get("parentUser")))
	case path == "service-accounts" && r.Method == http.MethodPost:
		s.adminAddSvcAcct(w, r, accessKey)
	case path == "service-accounts" && r.Method == http.MethodDelete:
		if err := s.iam.RemoveServiceAccount(q.Get("accessKey")); err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSONError(w, http.StatusNotFound, "unknown admin route")
	}
}

func (s *Server) adminInfo(w http.ResponseWriter, r *http.Request) {
	si, _ := s.obj.StorageInfo(r.Context())
	var total, free uint64
	for _, d := range si.Disks {
		total += d.TotalSpace
		free += d.FreeSpace
	}
	info := map[string]any{
		"version":         "gostore",
		"mode":            backendMode(si.Backend.Type),
		"region":          s.cfg.Region,
		"drives":          len(si.Disks),
		"totalSpace":      total,
		"freeSpace":       free,
		"parity":          si.Backend.StandardSCParity,
		"users":           len(s.iam.ListUsers()),
		"serviceAccounts": len(s.iam.ListServiceAccounts("")),
		"policies":        len(s.iam.ListPolicies()),
	}
	if d, ok := s.obj.(interface {
		DataDir() string
		FormatCreated() string
		FreshlyFormatted() bool
	}); ok {
		info["dataDir"] = d.DataDir()
		info["dataInitialized"] = d.FormatCreated()
		info["volumeWasEmptyAtBoot"] = d.FreshlyFormatted()
	}
	info["dedup"] = erasure.DedupEnabled()
	info["readOnly"] = s.ro.on()
	if tn := erasure.TierNames(); len(tn) > 0 {
		info["tiers"] = tn
	}
	if km, ok := s.obj.(interface{ KMSMode() string }); ok {
		info["kms"] = km.KMSMode()
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) adminHeal(w http.ResponseWriter, r *http.Request) {
	pool, ok := s.obj.(*erasure.Pool)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "no-op", "reason": "single-disk backend has no redundancy to heal",
		})
		return
	}
	rep, err := pool.Heal(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) erasurePool() (*erasure.Pool, bool) {
	p, ok := s.obj.(*erasure.Pool)
	return p, ok
}

func (s *Server) adminPoolStatus(w http.ResponseWriter) {
	pool, ok := s.erasurePool()
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"sets": 1, "draining": []int{}})
		return
	}
	writeJSON(w, http.StatusOK, pool.PoolStatus())
}

func (s *Server) adminPoolDecommission(w http.ResponseWriter, r *http.Request) {
	pool, ok := s.erasurePool()
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "not an erasure pool")
		return
	}
	idx, err := strconv.Atoi(r.URL.Query().Get("set"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "set query param must be an integer")
		return
	}
	if err := pool.Decommission(r.Context(), idx); err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, pool.PoolStatus())
}

func (s *Server) adminPoolRebalance(w http.ResponseWriter) {
	pool, ok := s.erasurePool()
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "not an erasure pool")
		return
	}
	if err := pool.Rebalance(context.Background()); err != nil {
		writeJSONError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, pool.PoolStatus())
}

func backendMode(t string) string {
	switch t {
	case "erasure":
		return "erasure"
	case "single":
		return "single-disk"
	default:
		return t
	}
}

func (s *Server) adminAddUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessKey string   `json:"accessKey"`
		SecretKey string   `json:"secretKey"`
		Policies  []string `json:"policies"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := s.iam.AddUser(body.AccessKey, body.SecretKey, body.Policies); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, iam.UserInfo{AccessKey: body.AccessKey, Policies: body.Policies, Status: "enabled"})
}

// adminRotateSecret gives a user a fresh secret key (same access key). Body:
// {"accessKey":"...", "secretKey":"..."(optional)}. Returns it once.
func (s *Server) adminRotateSecret(w http.ResponseWriter, r *http.Request) {
	var body struct{ AccessKey, SecretKey string }
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.SecretKey == "" {
		body.SecretKey = storage.NewID() + storage.NewID()[:8]
	}
	if err := s.iam.SetUserSecret(body.AccessKey, body.SecretKey); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"accessKey": body.AccessKey, "secretKey": body.SecretKey})
}

// adminEmptyBucket deletes every object in a bucket (all versions) without
// deleting the bucket itself. MinIO makes you clear objects first by hand.
func (s *Server) adminEmptyBucket(w http.ResponseWriter, r *http.Request) {
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		writeJSONError(w, http.StatusBadRequest, "bucket query param required")
		return
	}
	ctx := r.Context()
	deleted := 0
	token := ""
	for {
		li, err := s.obj.ListObjectsV2(ctx, bucket, "", token, "", 1000, false, "")
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(li.Objects) == 0 {
			break
		}
		batch := make([]object.ObjectToDelete, 0, len(li.Objects))
		for _, o := range li.Objects {
			batch = append(batch, object.ObjectToDelete{ObjectName: o.Name})
		}
		dr, _ := s.obj.DeleteObjects(ctx, bucket, batch, object.ObjectOptions{})
		deleted += len(dr)
		if !li.IsTruncated {
			break
		}
		token = li.NextContinuationToken
	}
	// also sweep version logs / delete markers
	lv, _ := s.obj.ListObjectVersions(ctx, bucket, "", "", "", "", 1000)
	for _, o := range lv.Objects {
		if o.VersionID != "" && o.VersionID != "null" {
			_, _ = s.obj.DeleteObject(ctx, bucket, o.Name, object.ObjectOptions{VersionID: o.VersionID})
			deleted++
		}
	}
	s.ocache.evictBucket(bucket)
	writeJSON(w, http.StatusOK, map[string]any{"bucket": bucket, "deleted": deleted})
}

// adminWhoami reports the caller's own identity + effective policies.
func (s *Server) adminWhoami(w http.ResponseWriter, accessKey string, isAdmin bool) {
	id, ok := s.iam.Identity(accessKey)
	out := map[string]any{"accessKey": accessKey, "isAdmin": isAdmin}
	if ok {
		out["isRoot"] = id.IsRoot
		out["parentUser"] = id.ParentUser
		out["policies"] = id.Policies
		if !id.Expiry.IsZero() {
			out["expiresAt"] = id.Expiry
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminAddSvcAcct(w http.ResponseWriter, r *http.Request, caller string) {
	var body struct {
		ParentUser string `json:"parentUser"`
		AccessKey  string `json:"accessKey"`
		SecretKey  string `json:"secretKey"`
		Policy     string `json:"policy"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.ParentUser == "" {
		body.ParentUser = caller
	}
	if body.AccessKey == "" {
		body.AccessKey = storage.NewID()[:20]
	}
	if body.SecretKey == "" {
		body.SecretKey = storage.NewID() + storage.NewID()[:8]
	}
	if err := s.iam.AddServiceAccount(body.ParentUser, body.AccessKey, body.SecretKey, body.Policy); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"accessKey": body.AccessKey, "secretKey": body.SecretKey, "parentUser": body.ParentUser,
	})
}

// --- small JSON helpers -------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body: "+err.Error())
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}
