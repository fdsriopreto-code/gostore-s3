// Package bucketcfg stores the per-bucket configuration the S3 API layer
// owns (policy, CORS, tag set, event notifications, versioning, object lock,
// replication, lifecycle) as a single JSON blob persisted through
// configstore.Backend — i.e. as an object replicated across every disk of
// every erasure set, so the config is cluster-wide with no external
// database. It is intentionally separate from the object backend's own
// bucket bookkeeping.
package bucketcfg

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/logger"
)

// Config is one bucket's API-level configuration.
type Config struct {
	Policy       json.RawMessage   `json:"policy,omitempty"` // raw bucket policy document
	CORS         []CORSRule        `json:"cors,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Notification *Notification     `json:"notification,omitempty"`
	// Versioning is "", "Enabled" or "Suspended" (S3 VersioningConfiguration).
	Versioning string `json:"versioning,omitempty"`
	// ObjectLock, when set, means the bucket was created with Object Lock and
	// optionally carries a default retention rule applied to new objects.
	ObjectLock *ObjectLockConfig `json:"objectLock,omitempty"`
	// Replication rules copy object writes/deletes to a destination.
	Replication []ReplicationRule `json:"replication,omitempty"`
	// Lifecycle rules expire objects / noncurrent versions / stale uploads.
	Lifecycle []LifecycleRule `json:"lifecycle,omitempty"`

	// QuotaBytes / QuotaObjects cap a bucket's total size / object count.
	// 0 = no limit. Enforced against the scanner's last usage snapshot, so
	// it is a soft (eventually-consistent) quota.
	QuotaBytes   int64 `json:"quotaBytes,omitempty"`
	QuotaObjects int64 `json:"quotaObjects,omitempty"`

	// Website, when set, turns the bucket into a static site: a GET for "/"
	// or a "dir/" path serves IndexDocument, and a miss serves ErrorDocument.
	Website *WebsiteConfig `json:"website,omitempty"`

	// Compress stores new objects zstd-compressed at rest (erasure backend,
	// non-SSE, single-part; already-compressed content-types are skipped).
	Compress bool `json:"compress,omitempty"`

	// Encryption, when "AES256", applies SSE-S3 at rest to every new object
	// that doesn't already request encryption (S3 "default bucket
	// encryption"). Empty = off.
	Encryption string `json:"encryption,omitempty"`

	// IngestKeys are long-lived, write-only, prefix-scoped upload tokens for
	// the /gostore/ingest/ endpoint — so any backend can drop a backup with a
	// single header, no SigV4.
	IngestKeys []IngestKey `json:"ingestKeys,omitempty"`
}

// IngestKey is one prefix-scoped write-only upload token. Only the token's
// sha256 is stored.
type IngestKey struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"` // sha256 hex of the secret token
	Prefix    string    `json:"prefix,omitempty"`
	Label     string    `json:"label,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// WebsiteConfig is the static-website-hosting configuration for a bucket.
type WebsiteConfig struct {
	IndexDocument string `json:"indexDocument,omitempty"` // e.g. "index.html"
	ErrorDocument string `json:"errorDocument,omitempty"` // e.g. "404.html"
}

// LifecycleRule is a subset of an S3 lifecycle rule.
type LifecycleRule struct {
	ID     string `json:"id"`
	Prefix string `json:"prefix,omitempty"`
	Status string `json:"status"` // "Enabled" | "Disabled"

	ExpirationDays                  int    `json:"expirationDays,omitempty"`
	ExpirationDate                  string `json:"expirationDate,omitempty"` // RFC3339
	ExpiredObjectDeleteMarker       bool   `json:"expiredObjectDeleteMarker,omitempty"`
	NoncurrentVersionExpirationDays int    `json:"noncurrentVersionExpirationDays,omitempty"`
	AbortIncompleteMultipartDays    int    `json:"abortIncompleteMultipartUploadDays,omitempty"`

	// Transition moves an object's bytes to a remote cold tier (a name
	// registered via GOSTORE_TIER_<NAME>) once it is TransitionDays old.
	TransitionDays int    `json:"transitionDays,omitempty"`
	TransitionTier string `json:"transitionTier,omitempty"`
}

// ReplicationRule copies matching objects to a destination bucket — local
// (DestEndpoint empty) or a remote S3-compatible endpoint.
type ReplicationRule struct {
	ID            string `json:"id"`
	Prefix        string `json:"prefix,omitempty"`
	DestBucket    string `json:"destBucket"`
	DestEndpoint  string `json:"destEndpoint,omitempty"` // https://host  (empty = this server)
	DestRegion    string `json:"destRegion,omitempty"`
	DestAccessKey string `json:"destAccessKey,omitempty"`
	DestSecretKey string `json:"destSecretKey,omitempty"`
	DeleteRepl    bool   `json:"deleteReplication,omitempty"` // also replicate deletes
}

// ObjectLockConfig is the bucket default retention rule.
type ObjectLockConfig struct {
	Enabled      bool   `json:"enabled"`
	DefaultMode  string `json:"defaultMode,omitempty"` // GOVERNANCE | COMPLIANCE
	DefaultDays  int    `json:"defaultDays,omitempty"`
	DefaultYears int    `json:"defaultYears,omitempty"`
}

// CORSRule mirrors an S3 CORS rule.
type CORSRule struct {
	AllowedOrigins []string `json:"allowedOrigins"`
	AllowedMethods []string `json:"allowedMethods"`
	AllowedHeaders []string `json:"allowedHeaders,omitempty"`
	ExposeHeaders  []string `json:"exposeHeaders,omitempty"`
	MaxAgeSeconds  int      `json:"maxAgeSeconds,omitempty"`
}

// Notification is a minimal bucket notification config: fire webhooks on
// object create/remove events matching optional prefix/suffix.
type Notification struct {
	Webhooks []WebhookTarget `json:"webhooks,omitempty"`
}

// WebhookTarget is one notification endpoint.
type WebhookTarget struct {
	ID     string   `json:"id"`
	URL    string   `json:"url"`
	Events []string `json:"events"` // "s3:ObjectCreated:*", "s3:ObjectRemoved:*"
	Prefix string   `json:"prefix,omitempty"`
	Suffix string   `json:"suffix,omitempty"`
}

const storeKey = "bucketcfg/config.json"

// envelope is the on-wire shape: the bucket map plus a version stamp the
// cluster refresher compares.
type envelope struct {
	Buckets   map[string]*Config `json:"buckets"`
	UpdatedAt time.Time          `json:"updatedAt"`
}

// Store is the config store, backed by configstore.Backend.
type Store struct {
	mu       sync.RWMutex
	be       configstore.Backend
	all      map[string]*Config
	lastSync time.Time
}

// Open loads (or initialises) the store from the object backend.
func Open(be configstore.Backend) (*Store, error) {
	s := &Store{be: be, all: map[string]*Config{}}
	b, err := be.ReadConfig(context.Background(), storeKey)
	if err != nil && !errors.Is(err, configstore.ErrNotFound) {
		return nil, err
	}
	if err == nil {
		s.loadBytes(b)
	}
	return s, nil
}

// loadBytes accepts either the current envelope shape or the legacy bare
// map[string]*Config, so an in-place upgrade keeps its data.
func (s *Store) loadBytes(b []byte) {
	var env envelope
	if json.Unmarshal(b, &env) == nil && env.Buckets != nil {
		s.all = env.Buckets
		s.lastSync = env.UpdatedAt
		return
	}
	var m map[string]*Config
	if json.Unmarshal(b, &m) == nil && m != nil {
		s.all = m
	}
}

// StartRefresh polls the store and re-applies any version newer than the one
// this node last wrote (cluster propagation of bucket policy/versioning/etc).
func (s *Store) StartRefresh(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	go func() {
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b, err := s.be.ReadConfig(ctx, storeKey)
				if err != nil {
					continue
				}
				var env envelope
				if json.Unmarshal(b, &env) != nil || env.Buckets == nil {
					continue
				}
				s.mu.Lock()
				if env.UpdatedAt.After(s.lastSync) {
					s.all = env.Buckets
					s.lastSync = env.UpdatedAt
					logger.Debug("bucketcfg: applied newer state from store", "updatedAt", env.UpdatedAt)
				}
				s.mu.Unlock()
			}
		}
	}()
}

// Get returns a copy of the bucket config (never nil).
func (s *Store) Get(bucket string) *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.all[bucket]
	if !ok || c == nil {
		return &Config{}
	}
	cp := *c
	return &cp
}

// Update applies fn to the bucket's config and persists.
func (s *Store) Update(bucket string, fn func(*Config)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.all[bucket]
	if c == nil {
		c = &Config{}
	}
	fn(c)
	s.all[bucket] = c
	return s.saveLocked()
}

// Delete removes a bucket's config entirely (on DeleteBucket).
func (s *Store) Delete(bucket string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.all, bucket)
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	now := time.Now().UTC()
	env := envelope{Buckets: s.all, UpdatedAt: now}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	if err := s.be.WriteConfig(context.Background(), storeKey, b); err != nil {
		return err
	}
	s.lastSync = now
	return nil
}
