package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/erasure"
	"github.com/lojadopocket/gostore/internal/logger"
	"github.com/lojadopocket/gostore/internal/object"
)

// Scheduled self-backup: when enabled, gostore periodically mirrors every
// object to a registered remote tier (GOSTORE_TIER_<NAME>). Incremental — an
// object is skipped when the remote already has it at the same size.

const backupCfgKey = "backup/config"

type backupConfig struct {
	Enabled       bool   `json:"enabled"`
	Tier          string `json:"tier"`
	IntervalHours int    `json:"intervalHours"`
	Prefix        string `json:"prefix,omitempty"` // only back up keys under this (per-bucket)
}

type backupStatus struct {
	Running     bool      `json:"running"`
	LastRun     time.Time `json:"lastRun,omitempty"`
	LastError   string    `json:"lastError,omitempty"`
	Copied      int64     `json:"copied"`
	Skipped     int64     `json:"skipped"`
	Errors      int64     `json:"errors"`
	BytesCopied int64     `json:"bytesCopied"`
}

type backupJob struct {
	obj     object.Layer
	cstore  configstore.Backend
	status  atomic.Pointer[backupStatus]
	running atomic.Bool

	restoreStat    atomic.Pointer[restoreStatus]
	restoreRunning atomic.Bool
}

// restoreStatus tracks a pull-back (disaster recovery) from the backup tier.
type restoreStatus struct {
	Running   bool      `json:"running"`
	LastRun   time.Time `json:"lastRun,omitempty"`
	LastError string    `json:"lastError,omitempty"`
	Overwrite bool      `json:"overwrite"`
	Restored  int64     `json:"restored"`
	Skipped   int64     `json:"skipped"`
	Errors    int64     `json:"errors"`
}

func cloneRS(s *restoreStatus) *restoreStatus { c := *s; return &c }

// restore pulls every object from the configured backup tier back into the
// local store — disaster recovery after data loss. By default it only writes
// objects that are MISSING locally (never clobbers newer local data); with
// overwrite it replaces them. Single-flight.
func (j *backupJob) restore(ctx context.Context, overwrite bool) {
	if !j.restoreRunning.CompareAndSwap(false, true) {
		return
	}
	defer j.restoreRunning.Store(false)

	st := &restoreStatus{Running: true, LastRun: time.Now().UTC(), Overwrite: overwrite}
	j.restoreStat.Store(st)
	cl := erasure.TierClient(j.config().Tier)
	if cl == nil {
		st.Running, st.LastError = false, "no backup tier is configured"
		j.restoreStat.Store(cloneRS(st))
		return
	}

	token := ""
	for {
		if ctx.Err() != nil {
			break
		}
		entries, next, err := cl.List(ctx, token)
		if err != nil {
			st.Errors++
			st.LastError = err.Error()
			break
		}
		for _, e := range entries {
			if ctx.Err() != nil {
				break
			}
			// Remote keys are "<prefix><bucket>/<objectKey>"; strip the tier
			// prefix and split off the bucket.
			lk := strings.TrimPrefix(e.Key, cl.Prefix)
			slash := strings.IndexByte(lk, '/')
			if slash <= 0 || slash == len(lk)-1 {
				continue
			}
			bkt, obj := lk[:slash], lk[slash+1:]
			if !overwrite {
				if _, gerr := j.obj.GetObjectInfo(ctx, bkt, obj, object.ObjectOptions{}); gerr == nil {
					st.Skipped++
					j.restoreStat.Store(cloneRS(st))
					continue
				}
			}
			_ = j.obj.MakeBucket(ctx, bkt, object.MakeBucketOptions{})
			rc, _, gerr := cl.Get(ctx, lk)
			if gerr != nil {
				st.Errors++
				st.LastError = gerr.Error()
				continue
			}
			pr := object.NewPutObjReader(rc, e.Size, e.Size)
			_, perr := j.obj.PutObject(ctx, bkt, obj, pr, object.ObjectOptions{})
			rc.Close()
			if perr != nil {
				st.Errors++
				st.LastError = perr.Error()
			} else {
				st.Restored++
			}
			j.restoreStat.Store(cloneRS(st))
		}
		if next == "" {
			break
		}
		token = next
	}
	st.Running = false
	j.restoreStat.Store(st)
}

func newBackupJob(obj object.Layer) *backupJob {
	cs, _ := obj.(configstore.Backend)
	return &backupJob{obj: obj, cstore: cs}
}

func (j *backupJob) config() backupConfig {
	var c backupConfig
	if j.cstore == nil {
		return c
	}
	if b, err := j.cstore.ReadConfig(context.Background(), backupCfgKey); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func (j *backupJob) setConfig(c backupConfig) error {
	if j.cstore == nil {
		return configstore.ErrNotFound
	}
	b, _ := json.Marshal(c)
	return j.cstore.WriteConfig(context.Background(), backupCfgKey, b)
}

// loop runs the backup on its configured cadence.
func (j *backupJob) loop(ctx context.Context) {
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c := j.config()
			if !c.Enabled || c.Tier == "" {
				continue
			}
			iv := time.Duration(c.IntervalHours) * time.Hour
			if iv <= 0 {
				iv = 24 * time.Hour
			}
			st := j.status.Load()
			if st != nil && time.Since(st.LastRun) < iv {
				continue
			}
			j.run(ctx)
		}
	}
}

// run mirrors every object to the configured tier once. Single-flight.
func (j *backupJob) run(ctx context.Context) {
	if !j.running.CompareAndSwap(false, true) {
		return
	}
	defer j.running.Store(false)

	c := j.config()
	cl := erasure.TierClient(c.Tier)
	if cl == nil {
		j.status.Store(&backupStatus{LastRun: time.Now().UTC(), LastError: "tier " + c.Tier + " is not configured (GOSTORE_TIER_" + c.Tier + ")"})
		return
	}
	st := &backupStatus{Running: true, LastRun: time.Now().UTC()}
	j.status.Store(st)

	buckets, err := j.obj.ListBuckets(ctx)
	if err != nil {
		st.Running, st.LastError = false, err.Error()
		j.status.Store(clone(st))
		return
	}
	for _, b := range buckets {
		token := ""
		for {
			if ctx.Err() != nil {
				break
			}
			li, lerr := j.obj.ListObjectsV2(ctx, b.Name, c.Prefix, token, "", 1000, false, "")
			if lerr != nil {
				st.Errors++
				break
			}
			for _, o := range li.Objects {
				if ctx.Err() != nil {
					break
				}
				rk := b.Name + "/" + o.Name
				if exists, sz, _, herr := cl.Head(ctx, rk); herr == nil && exists && sz == o.Size {
					st.Skipped++
					j.status.Store(clone(st))
					continue
				}
				gr, gerr := j.obj.GetObjectNInfo(ctx, b.Name, o.Name, nil, nil, object.ObjectOptions{})
				if gerr != nil {
					st.Errors++
					continue
				}
				perr := cl.Put(ctx, rk, gr, o.Size, o.ContentType)
				gr.Close()
				if perr != nil {
					st.Errors++
					st.LastError = perr.Error()
				} else {
					st.Copied++
					st.BytesCopied += o.Size
				}
				j.status.Store(clone(st))
			}
			if !li.IsTruncated {
				break
			}
			token = li.NextContinuationToken
		}
	}
	st.Running = false
	j.status.Store(st)
}

func clone(s *backupStatus) *backupStatus { c := *s; return &c }

// --- admin routes ----------------------------------------------------

func (s *Server) handleAdminBackup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		out := map[string]any{"config": s.backup.config(), "tiers": erasure.TierNames()}
		if st := s.backup.status.Load(); st != nil {
			out["status"] = st
		}
		if rs := s.backup.restoreStat.Load(); rs != nil {
			out["restore"] = rs
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPut:
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var c backupConfig
		if json.Unmarshal(b, &c) != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if c.Enabled && erasure.TierClient(c.Tier) == nil {
			writeJSONError(w, http.StatusBadRequest, "tier "+c.Tier+" is not configured (set GOSTORE_TIER_"+c.Tier+")")
			return
		}
		if err := s.backup.setConfig(c); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, c)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "GET or PUT")
	}
}

func (s *Server) handleAdminBackupRun(w http.ResponseWriter, r *http.Request) {
	go s.backup.run(context.Background())
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true})
}

// handleAdminReplicationBackfill enqueues every existing object in a bucket
// for replication, so a newly-added rule covers pre-existing data.
func (s *Server) handleAdminReplicationBackfill(w http.ResponseWriter, r *http.Request) {
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		writeJSONError(w, http.StatusBadRequest, "bucket query param required")
		return
	}
	go func() {
		n, err := s.repl.Backfill(context.Background(), bucket)
		if err != nil {
			logger.Warn("replication backfill error", "bucket", bucket, "enqueued", n, "err", err)
		} else {
			logger.Info("replication backfill enqueued", "bucket", bucket, "objects", n)
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "bucket": bucket})
}

// handleAdminBackupRestore pulls objects back from the backup tier into the
// local store (disaster recovery). ?overwrite=1 replaces existing objects;
// by default only missing objects are restored.
func (s *Server) handleAdminBackupRestore(w http.ResponseWriter, r *http.Request) {
	if s.ro.on() {
		writeJSONError(w, http.StatusConflict, "server is read-only")
		return
	}
	overwrite := r.URL.Query().Get("overwrite") == "1" || r.URL.Query().Get("overwrite") == "true"
	go s.backup.restore(context.Background(), overwrite)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "overwrite": overwrite})
}
