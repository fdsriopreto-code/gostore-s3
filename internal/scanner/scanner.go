// Package scanner runs a periodic background pass over every bucket. It
// applies lifecycle (ILM) rules — object expiration, noncurrent-version
// expiration, aborting stale multipart uploads — and while it is already
// walking the namespace it also accumulates per-bucket data-usage stats and
// opportunistically heals a sample of objects (erasure backend).
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/logger"
	"github.com/lojadopocket/gostore/internal/metrics"
	"github.com/lojadopocket/gostore/internal/object"
)

// usageSnapKey stores the last data-usage snapshot so per-bucket counts and
// sizes are available immediately after a restart, instead of being blank
// until the next scan completes (up to an hour later). Only the lightweight
// per-bucket totals are persisted — the large per-prefix map is not.
const usageSnapKey = "datausage/snapshot.json"

// objectHealer is implemented by the erasure backend: repair one object's
// missing/corrupt shards and metadata in place.
type objectHealer interface {
	HealObject(ctx context.Context, bucket, key string) error
}

// dedupGCer is implemented by the erasure backend when content-addressed
// dedup is enabled: remove CAS blobs no object references.
type dedupGCer interface {
	GCDedup(ctx context.Context, grace time.Duration) (int, error)
}

// healSampleRate: 1-in-N objects are opportunistically healed per pass
// (matches MinIO's data-scanner sampling idea).
const healSampleRate = 128

// BucketUsage is the accounted size of one bucket.
type BucketUsage struct {
	Objects int64 `json:"objects"`
	Bytes   int64 `json:"bytes"`
}

// DataUsage is the result of the most recent accounting pass.
type DataUsage struct {
	LastUpdate   time.Time              `json:"lastUpdate"`
	Buckets      map[string]BucketUsage `json:"buckets"`
	TotalObjects int64                  `json:"totalObjects"`
	TotalBytes   int64                  `json:"totalBytes"`

	// Prefixes holds recursive usage for every "folder" (each "/"-terminated
	// ancestor path of a key), keyed "<bucket>\x00<prefix>". Capped to keep
	// memory bounded on pathological namespaces.
	Prefixes map[string]BucketUsage `json:"-"`
}

// prefixUsageMax caps how many distinct folder prefixes the accounting pass
// tracks (see DataUsage.Prefixes).
const prefixUsageMax = 200_000

// addPrefixUsage credits size to every "/"-terminated ancestor folder of key
// (plus the bucket root ""), bounded by prefixUsageMax.
func addPrefixUsage(m map[string]BucketUsage, bucket, key string, size int64) {
	if m == nil {
		return
	}
	credit := func(prefix string) {
		k := bucket + "\x00" + prefix
		u, ok := m[k]
		if !ok && len(m) >= prefixUsageMax {
			return
		}
		u.Objects++
		u.Bytes += size
		m[k] = u
	}
	credit("") // bucket root
	for i := 0; i < len(key); i++ {
		if key[i] == '/' {
			credit(key[:i+1])
		}
	}
}

// PrefixUsage returns the recursive usage of one folder prefix (must end with
// "/", or "" for the bucket root) and its immediate child folders.
func (s *Scanner) PrefixUsage(bucket, prefix string) (self BucketUsage, children map[string]BucketUsage) {
	children = map[string]BucketUsage{}
	u := s.usage.Load()
	if u == nil || u.Prefixes == nil {
		return
	}
	self = u.Prefixes[bucket+"\x00"+prefix]
	want := bucket + "\x00" + prefix
	for k, v := range u.Prefixes {
		if !strings.HasPrefix(k, want) || k == want {
			continue
		}
		rest := k[len(want):]
		// immediate child folder only: exactly one "/" and it's the last char
		if i := strings.IndexByte(rest, '/'); i == len(rest)-1 {
			children[rest] = v
		}
	}
	return
}

// Scanner walks the object layer on an interval.
type Scanner struct {
	obj      object.Layer
	cfg      *bucketcfg.Store
	interval time.Duration
	healer   objectHealer // nil if the backend can't heal

	usage       atomic.Pointer[DataUsage]
	healScanned uint64

	// Deep scrub: a guaranteed full pass that verifies (and repairs) every
	// object's shards, versus the 1-in-N heal sample the lifecycle pass does.
	scrubInterval time.Duration
	scrub         atomic.Pointer[ScrubStatus]
	scrubRunning  atomic.Bool

	// mpuTTL aborts incomplete multipart uploads older than this even when no
	// lifecycle rule covers them (AWS applies a default too). 0 disables.
	mpuTTL time.Duration

	// cstore persists the usage snapshot (nil if the backend has no config
	// store). Set in New.
	cstore configstore.Backend
}

// SetMultipartTTL sets the default abort age for abandoned multipart uploads.
func (s *Scanner) SetMultipartTTL(d time.Duration) { s.mpuTTL = d }

// ScrubStatus is the progress of the current or most recent deep scrub.
type ScrubStatus struct {
	Running       bool      `json:"running"`
	StartedAt     time.Time `json:"startedAt"`
	FinishedAt    time.Time `json:"finishedAt,omitempty"`
	Bucket        string    `json:"bucket,omitempty"`
	ObjectsDone   int64     `json:"objectsScanned"`
	Repaired      int64     `json:"objectsRepaired"`
	Unrecoverable int64     `json:"unrecoverable"`
	Errors        int64     `json:"errors"`
}

// New builds a Scanner. interval <= 0 defaults to one hour.
func New(obj object.Layer, cfg *bucketcfg.Store, interval time.Duration) *Scanner {
	if interval <= 0 {
		interval = time.Hour
	}
	s := &Scanner{obj: obj, cfg: cfg, interval: interval}
	if h, ok := obj.(objectHealer); ok {
		s.healer = h
	}
	if cb, ok := obj.(configstore.Backend); ok {
		s.cstore = cb
		s.loadUsage()
	}
	return s
}

// loadUsage warms the in-memory usage snapshot from the persisted copy so
// per-bucket counts/sizes are available right after a restart.
func (s *Scanner) loadUsage() {
	if s.cstore == nil {
		return
	}
	b, err := s.cstore.ReadConfig(context.Background(), usageSnapKey)
	if err != nil {
		return
	}
	var du DataUsage
	if json.Unmarshal(b, &du) != nil {
		return
	}
	if du.Buckets == nil {
		du.Buckets = map[string]BucketUsage{}
	}
	du.Prefixes = map[string]BucketUsage{} // not persisted; filled on next scan
	s.usage.Store(&du)
}

// saveUsage persists the lightweight per-bucket totals (Prefixes is json:"-"
// so it is never written). Best-effort.
func (s *Scanner) saveUsage(u *DataUsage) {
	if s.cstore == nil || u == nil {
		return
	}
	if b, err := json.Marshal(u); err == nil {
		_ = s.cstore.WriteConfig(context.Background(), usageSnapKey, b)
	}
}

// SetScrubInterval enables the periodic deep scrub (<=0 disables it).
func (s *Scanner) SetScrubInterval(d time.Duration) { s.scrubInterval = d }

// ScrubStatus returns the latest deep-scrub progress (nil if never run).
func (s *Scanner) ScrubStatus() *ScrubStatus { return s.scrub.Load() }

// Usage returns the most recent data-usage snapshot (nil before the first
// pass completes).
func (s *Scanner) Usage() *DataUsage { return s.usage.Load() }

// Run scans once immediately, then every interval, until ctx is done. When a
// scrub interval is set it also fires a throttled full deep scrub on that
// (longer) cadence.
func (s *Scanner) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	if rep := s.ScanOnce(ctx); rep.nonZero() {
		logger.Info("lifecycle scan", rep.args()...)
	}

	var scrubC <-chan time.Time
	if s.scrubInterval > 0 && s.healer != nil {
		st := time.NewTicker(s.scrubInterval)
		defer st.Stop()
		scrubC = st.C
		go s.DeepScrub(ctx) // one on startup, then on the ticker
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if rep := s.ScanOnce(ctx); rep.nonZero() {
				logger.Info("lifecycle scan", rep.args()...)
			}
		case <-scrubC:
			go s.DeepScrub(ctx)
		}
	}
}

// DeepScrub verifies and repairs every object in every bucket — the
// guaranteed full pass. It is heavily rate-limited by the backend's heal
// throttle so it never starves client I/O, and skips itself if one is
// already running.
func (s *Scanner) DeepScrub(ctx context.Context) {
	if s.healer == nil || !s.scrubRunning.CompareAndSwap(false, true) {
		return
	}
	defer s.scrubRunning.Store(false)

	st := &ScrubStatus{Running: true, StartedAt: time.Now().UTC()}
	s.scrub.Store(st)
	logger.Info("deep scrub started")

	buckets, err := s.obj.ListBuckets(ctx)
	if err != nil {
		st.Errors++
		st.Running, st.FinishedAt = false, time.Now().UTC()
		s.scrub.Store(st)
		return
	}
	for _, b := range buckets {
		st.Bucket = b.Name
		token := ""
		for {
			if ctx.Err() != nil {
				break
			}
			li, err := s.obj.ListObjectsV2(ctx, b.Name, "", token, "", 1000, false, "")
			if err != nil {
				st.Errors++
				break
			}
			for _, o := range li.Objects {
				if ctx.Err() != nil {
					break
				}
				err := s.healer.HealObject(ctx, b.Name, o.Name) // throttled inside
				st.ObjectsDone++
				switch {
				case err == nil:
				case isUnrecoverable(err):
					st.Unrecoverable++
				default:
					st.Errors++
				}
				s.scrub.Store(cloneScrub(st))
			}
			if !li.IsTruncated {
				break
			}
			token = li.NextContinuationToken
		}
	}
	// Mark-and-sweep GC of unreferenced dedup blobs (grace window guards a
	// PUT that installed a blob but hasn't committed its xl.meta yet).
	if gc, ok := s.obj.(dedupGCer); ok && ctx.Err() == nil {
		if n, err := gc.GCDedup(ctx, time.Hour); err == nil && n > 0 {
			logger.Info("dedup GC removed unreferenced blobs", "count", n)
		}
	}

	st.Running, st.FinishedAt, st.Bucket = false, time.Now().UTC(), ""
	s.scrub.Store(st)
	logger.Info("deep scrub complete",
		"objects", st.ObjectsDone, "unrecoverable", st.Unrecoverable, "errors", st.Errors)
}

func cloneScrub(s *ScrubStatus) *ScrubStatus { c := *s; return &c }

func isUnrecoverable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "quorum")
}

// Report summarises a scan pass.
type Report struct {
	BucketsScanned  int `json:"bucketsScanned"`
	ObjectsExpired  int `json:"objectsExpired"`
	VersionsExpired int `json:"noncurrentVersionsExpired"`
	UploadsAborted  int `json:"multipartUploadsAborted"`
	ObjectsHealed   int `json:"objectsHealed"`
	ObjectsTiered   int `json:"objectsTiered"`
	Errors          int `json:"errors"`
}

func (r Report) nonZero() bool {
	return r.ObjectsExpired+r.VersionsExpired+r.UploadsAborted+r.ObjectsHealed+r.ObjectsTiered+r.Errors > 0
}
func (r Report) args() []any {
	return []any{
		"buckets", r.BucketsScanned, "objectsExpired", r.ObjectsExpired,
		"versionsExpired", r.VersionsExpired, "uploadsAborted", r.UploadsAborted,
		"objectsHealed", r.ObjectsHealed, "objectsTiered", r.ObjectsTiered, "errors", r.Errors,
	}
}

// objectTransitioner is implemented by the erasure backend: move an object's
// bytes to a named remote cold tier and leave a stub.
type objectTransitioner interface {
	TransitionObject(ctx context.Context, bucket, key, tier string) error
}

// expRule is a lifecycle rule pre-parsed for the walk.
type expRule struct {
	prefix     string
	days       int
	date       time.Time
	noncurrent int
	abortMPU   int
	transDays  int
	transTier  string
}

func enabledRules(rules []bucketcfg.LifecycleRule) []expRule {
	var out []expRule
	for _, r := range rules {
		if r.Status != "Enabled" {
			continue
		}
		er := expRule{prefix: r.Prefix, days: r.ExpirationDays,
			noncurrent: r.NoncurrentVersionExpirationDays, abortMPU: r.AbortIncompleteMultipartDays,
			transDays: r.TransitionDays, transTier: r.TransitionTier}
		if r.ExpirationDate != "" {
			if t, err := time.Parse(time.RFC3339, r.ExpirationDate); err == nil {
				er.date = t
			}
		}
		out = append(out, er)
	}
	return out
}

// ScanOnce runs a single pass and returns what it did.
func (s *Scanner) ScanOnce(ctx context.Context) Report {
	var rep Report
	buckets, err := s.obj.ListBuckets(ctx)
	if err != nil {
		rep.Errors++
		return rep
	}
	now := time.Now().UTC()

	usage := &DataUsage{LastUpdate: now, Buckets: map[string]BucketUsage{}, Prefixes: map[string]BucketUsage{}}
	for _, b := range buckets {
		rules := enabledRules(s.cfg.Get(b.Name).Lifecycle)

		// One walk of the bucket: usage + opportunistic heal + current-version
		// expiration for every rule (was one full ListObjects pass per rule).
		bu := s.walkBucket(ctx, b.Name, rules, now, &rep, usage.Prefixes)
		usage.Buckets[b.Name] = bu
		usage.TotalObjects += bu.Objects
		usage.TotalBytes += bu.Bytes

		// Abandoned multipart uploads: aborted per matching lifecycle rule, or
		// after mpuTTL when nothing covers them.
		s.abortStaleUploads(ctx, b.Name, rules, now, &rep)

		if len(rules) == 0 {
			continue
		}
		rep.BucketsScanned++
		s.expireNoncurrent(ctx, b.Name, rules, now, &rep)
	}
	s.usage.Store(usage)
	s.saveUsage(usage)
	return rep
}

// walkBucket lists every object once: tallies size, heals a
// 1-in-healSampleRate sample, and applies current-version expiration.
func (s *Scanner) walkBucket(ctx context.Context, bucket string, rules []expRule, now time.Time, rep *Report, prefixes map[string]BucketUsage) BucketUsage {
	var bu BucketUsage
	token := ""
	for {
		li, err := s.obj.ListObjectsV2(ctx, bucket, "", token, "", 1000, false, "")
		if err != nil {
			rep.Errors++
			return bu
		}
		for _, o := range li.Objects {
			bu.Objects++
			bu.Bytes += o.Size
			addPrefixUsage(prefixes, bucket, o.Name, o.Size)

			// Per-object TTL (gostore extension): a stored absolute-expiry
			// metadata key, enforced here regardless of lifecycle rules.
			if object.HasExpired(o.UserDefined, now) {
				if _, err := s.obj.DeleteObject(ctx, bucket, o.Name, object.ObjectOptions{Versioned: true}); err != nil {
					if !errors.Is(err, object.ErrObjectLocked) {
						rep.Errors++
					}
				} else {
					rep.ObjectsExpired++
					bu.Objects--
					bu.Bytes -= o.Size
				}
				continue
			}

			if s.healer != nil && s.shouldHeal(bucket, o.Name) {
				err := s.healer.HealObject(ctx, bucket, o.Name)
				metrics.HealResult(err == nil)
				if err == nil {
					rep.ObjectsHealed++
				} else {
					rep.Errors++
				}
			}
			expired := false
			for _, r := range rules {
				if (r.days <= 0 && r.date.IsZero()) || !strings.HasPrefix(o.Name, r.prefix) {
					continue
				}
				if !dueForExpiry(o.ModTime, r.days, r.date, now) {
					continue
				}
				if _, err := s.obj.DeleteObject(ctx, bucket, o.Name, object.ObjectOptions{Versioned: true}); err != nil {
					if !errors.Is(err, object.ErrObjectLocked) {
						rep.Errors++
					}
				} else {
					rep.ObjectsExpired++
					expired = true
				}
				break
			}
			// Transition to a remote cold tier (only if not just expired).
			if !expired {
				if tr, ok := s.obj.(objectTransitioner); ok {
					for _, r := range rules {
						if r.transDays <= 0 || r.transTier == "" || !strings.HasPrefix(o.Name, r.prefix) {
							continue
						}
						if now.Sub(o.ModTime) < time.Duration(r.transDays)*24*time.Hour {
							continue
						}
						if err := tr.TransitionObject(ctx, bucket, o.Name, r.transTier); err != nil {
							if !errors.Is(err, object.ErrObjectLocked) {
								rep.Errors++
							}
						} else {
							rep.ObjectsTiered++
						}
						break
					}
				}
			}
		}
		if !li.IsTruncated {
			return bu
		}
		token = li.NextContinuationToken
	}
}

// expireNoncurrent removes noncurrent versions older than the smallest
// matching rule's threshold — one version listing for the whole bucket.
func (s *Scanner) expireNoncurrent(ctx context.Context, bucket string, rules []expRule, now time.Time, rep *Report) {
	want := false
	for _, r := range rules {
		if r.noncurrent > 0 {
			want = true
		}
	}
	if !want {
		return
	}
	lv, err := s.obj.ListObjectVersions(ctx, bucket, "", "", "", "", 1000)
	if err != nil {
		rep.Errors++
		return
	}
	for _, o := range lv.Objects {
		if o.IsLatest || o.VersionID == "" || o.VersionID == "null" {
			continue
		}
		days := 0
		for _, r := range rules {
			if r.noncurrent > 0 && strings.HasPrefix(o.Name, r.prefix) && (days == 0 || r.noncurrent < days) {
				days = r.noncurrent
			}
		}
		if days == 0 || now.Sub(o.ModTime) < time.Duration(days)*24*time.Hour {
			continue
		}
		if _, err := s.obj.DeleteObject(ctx, bucket, o.Name, object.ObjectOptions{VersionID: o.VersionID}); err != nil {
			if !errors.Is(err, object.ErrObjectLocked) {
				rep.Errors++
			}
			continue
		}
		rep.VersionsExpired++
	}
}

// abortStaleUploads aborts multipart uploads older than the smallest
// matching rule's threshold — one multipart listing for the whole bucket.
func (s *Scanner) abortStaleUploads(ctx context.Context, bucket string, rules []expRule, now time.Time, rep *Report) {
	haveRule := false
	for _, r := range rules {
		if r.abortMPU > 0 {
			haveRule = true
		}
	}
	if !haveRule && s.mpuTTL <= 0 {
		return
	}
	mu, err := s.obj.ListMultipartUploads(ctx, bucket, "", "", "", "", 1000)
	if err != nil {
		rep.Errors++
		return
	}
	for _, u := range mu.Uploads {
		// Smallest applicable threshold: a matching rule, else the default TTL.
		var threshold time.Duration
		for _, r := range rules {
			if r.abortMPU > 0 && strings.HasPrefix(u.Object, r.prefix) {
				d := time.Duration(r.abortMPU) * 24 * time.Hour
				if threshold == 0 || d < threshold {
					threshold = d
				}
			}
		}
		if s.mpuTTL > 0 && (threshold == 0 || s.mpuTTL < threshold) {
			threshold = s.mpuTTL
		}
		if threshold == 0 || u.Initiated.After(now.Add(-threshold)) {
			continue
		}
		if err := s.obj.AbortMultipartUpload(ctx, bucket, u.Object, u.UploadID, object.ObjectOptions{}); err != nil {
			rep.Errors++
			continue
		}
		rep.UploadsAborted++
	}
}

func (s *Scanner) shouldHeal(bucket, key string) bool {
	// Deterministic per-object sampling, plus a rotating offset so a
	// different slice is covered each pass.
	h := fnv.New32a()
	_, _ = h.Write([]byte(bucket + "/" + key))
	pass := uint32(atomic.AddUint64(&s.healScanned, 1) / 4096)
	return (h.Sum32()+pass)%healSampleRate == 0
}

func dueForExpiry(mod time.Time, days int, date, now time.Time) bool {
	if !date.IsZero() && now.After(date) {
		return true
	}
	return days > 0 && now.Sub(mod) >= time.Duration(days)*24*time.Hour
}
