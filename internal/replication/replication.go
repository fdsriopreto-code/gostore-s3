// Package replication asynchronously copies object create/delete events to a
// destination — another bucket on this server, or a remote S3-compatible
// endpoint (SigV4-signed). Events go through a durable queue persisted in the
// config store, so a transient destination outage or a restart does not drop
// them: pending events are reloaded on boot and retried with backoff until
// they succeed (or their rule is removed).
package replication

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/logger"
	"github.com/lojadopocket/gostore/internal/object"
)

// Op is the replicated operation.
type Op int

const (
	Put Op = iota
	Delete
)

// Event is a replication work item.
type Event struct {
	Op        Op
	Bucket    string
	Key       string
	VersionID string
}

// queueKey stores the persisted pending-replication queue.
const queueKey = "replication/queue.json"

// maxBackoff caps the retry delay for a failing destination.
const maxBackoff = 5 * time.Minute

// queued is a durable pending event. It references its rule by ID (resolved
// from bucketcfg at drain time) rather than copying the rule's secret key
// into the queue file.
type queued struct {
	Bucket   string    `json:"bucket"`
	Key      string    `json:"key"`
	Op       Op        `json:"op"`
	RuleID   string    `json:"ruleID"`
	Attempts int       `json:"attempts"`
	NextAt   time.Time `json:"nextAt"`
}

// Manager runs replication for a pool of buckets, backed by a durable queue.
type Manager struct {
	cfg    *bucketcfg.Store
	obj    object.Layer
	client *http.Client
	sem    chan struct{}

	cstore configstore.Backend // nil if the backend has no config store
	mu     sync.Mutex
	queue  map[string]*queued
	wake   chan struct{}
}

// New builds a Manager and reloads any persisted pending events.
func New(cfg *bucketcfg.Store, obj object.Layer) *Manager {
	m := &Manager{
		cfg: cfg, obj: obj,
		client: &http.Client{Timeout: 60 * time.Second},
		sem:    make(chan struct{}, 16),
		queue:  map[string]*queued{},
		wake:   make(chan struct{}, 1),
	}
	if cb, ok := obj.(configstore.Backend); ok {
		m.cstore = cb
		m.loadQueue()
	}
	return m
}

// Publish enqueues an event onto the durable queue for every matching rule.
// It returns immediately; the background worker drains the queue with retry.
func (m *Manager) Publish(e Event) {
	if m == nil || m.cfg == nil {
		return
	}
	rules := m.cfg.Get(e.Bucket).Replication
	changed := false
	now := time.Now()
	m.mu.Lock()
	for _, r := range rules {
		if r.Prefix != "" && !strings.HasPrefix(e.Key, r.Prefix) {
			continue
		}
		// A newer event for the same (bucket,key,rule) supersedes an older
		// pending one — the latest state is what we need to replicate.
		m.queue[qkey(e.Bucket, e.Key, r.ID)] = &queued{
			Bucket: e.Bucket, Key: e.Key, Op: e.Op, RuleID: r.ID, NextAt: now,
		}
		changed = true
	}
	m.mu.Unlock()
	if changed {
		m.persist()
		m.signal()
	}
}

// StartWorker drains the queue on a short tick (and whenever Publish signals)
// until ctx is done. Mount one per Manager.
func (m *Manager) StartWorker(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		m.DrainOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.wake:
		}
	}
}

// DrainOnce attempts every due pending event once, in parallel (bounded).
// Successful events are removed; failures are kept with exponential backoff;
// events whose rule no longer exists are dropped. Exported for tests.
func (m *Manager) DrainOnce(ctx context.Context) {
	now := time.Now()
	m.mu.Lock()
	due := make([]*queued, 0, len(m.queue))
	for _, q := range m.queue {
		if !q.NextAt.After(now) {
			due = append(due, q)
		}
	}
	m.mu.Unlock()
	if len(due) == 0 {
		return
	}

	var changed atomic.Bool
	var wg sync.WaitGroup
	for _, q := range due {
		rule, ok := m.resolveRule(q.Bucket, q.RuleID)
		if !ok {
			m.mu.Lock()
			delete(m.queue, qkey(q.Bucket, q.Key, q.RuleID))
			m.mu.Unlock()
			changed.Store(true)
			continue
		}
		wg.Add(1)
		m.sem <- struct{}{}
		go func(q *queued, rule bucketcfg.ReplicationRule) {
			defer wg.Done()
			defer func() { <-m.sem }()
			err := m.attempt(rule, Event{Op: q.Op, Bucket: q.Bucket, Key: q.Key})
			k := qkey(q.Bucket, q.Key, q.RuleID)
			m.mu.Lock()
			if cur := m.queue[k]; cur == q { // not superseded by a newer Publish
				if err == nil {
					delete(m.queue, k)
				} else {
					q.Attempts++
					q.NextAt = time.Now().Add(backoff(q.Attempts))
				}
			}
			m.mu.Unlock()
			changed.Store(true)
			if err != nil {
				logger.Warn("replication attempt failed (will retry)",
					"rule", rule.ID, "bucket", q.Bucket, "key", q.Key, "attempt", q.Attempts, "err", err)
			}
		}(q, rule)
	}
	wg.Wait()
	if changed.Load() {
		m.persist()
	}
}

// Pending reports how many events are waiting in the queue.
func (m *Manager) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.queue)
}

// Wait drains until the queue is empty or ctx is done (used on shutdown).
func (m *Manager) Wait(ctx context.Context) {
	for {
		m.DrainOnce(ctx)
		if m.Pending() == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (m *Manager) attempt(rule bucketcfg.ReplicationRule, e Event) error {
	if e.Op == Delete {
		return m.replicateDelete(rule, e)
	}
	return m.replicatePut(rule, e)
}

func (m *Manager) resolveRule(bucket, ruleID string) (bucketcfg.ReplicationRule, bool) {
	for _, r := range m.cfg.Get(bucket).Replication {
		if r.ID == ruleID {
			return r, true
		}
	}
	return bucketcfg.ReplicationRule{}, false
}

func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) loadQueue() {
	b, err := m.cstore.ReadConfig(context.Background(), queueKey)
	if err != nil {
		return
	}
	var list []*queued
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for _, q := range list {
		if q != nil {
			m.queue[qkey(q.Bucket, q.Key, q.RuleID)] = q
		}
	}
	if len(m.queue) > 0 {
		logger.Info("replication: reloaded pending queue", "pending", len(m.queue))
	}
}

func (m *Manager) persist() {
	if m.cstore == nil {
		return
	}
	m.mu.Lock()
	list := make([]*queued, 0, len(m.queue))
	for _, q := range m.queue {
		list = append(list, q)
	}
	m.mu.Unlock()
	if b, err := json.Marshal(list); err == nil {
		_ = m.cstore.WriteConfig(context.Background(), queueKey, b)
	}
}

func qkey(bucket, key, ruleID string) string {
	return bucket + "\x00" + key + "\x00" + ruleID
}

func backoff(attempts int) time.Duration {
	d := 2 * time.Second
	for i := 1; i < attempts && d < maxBackoff; i++ {
		d *= 2
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

func (m *Manager) replicatePut(rule bucketcfg.ReplicationRule, e Event) error {
	gr, err := m.obj.GetObjectNInfo(context.Background(), e.Bucket, e.Key, nil, nil, object.ObjectOptions{})
	if err != nil {
		return err
	}
	defer gr.Close()

	if rule.DestEndpoint == "" {
		// local destination bucket
		pr := object.NewPutObjReader(gr, gr.ObjInfo.Size, gr.ObjInfo.Size)
		ud := map[string]string{}
		for k, v := range gr.ObjInfo.UserDefined {
			ud[k] = v
		}
		_, err = m.obj.PutObject(context.Background(), rule.DestBucket, e.Key, pr, object.ObjectOptions{UserDefined: ud})
		return err
	}

	// remote S3 destination
	buf, err := io.ReadAll(gr)
	if err != nil {
		return err
	}
	ct := gr.ObjInfo.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	return m.signedRequest(rule, http.MethodPut, e.Key, buf, ct)
}

func (m *Manager) replicateDelete(rule bucketcfg.ReplicationRule, e Event) error {
	if rule.DestEndpoint == "" {
		_, err := m.obj.DeleteObject(context.Background(), rule.DestBucket, e.Key, object.ObjectOptions{})
		return err
	}
	return m.signedRequest(rule, http.MethodDelete, e.Key, nil, "")
}

// signedRequest sends a SigV4-signed request to the remote endpoint.
func (m *Manager) signedRequest(rule bucketcfg.ReplicationRule, method, key string, body []byte, contentType string) error {
	region := rule.DestRegion
	if region == "" {
		region = "us-east-1"
	}
	endpoint := strings.TrimRight(rule.DestEndpoint, "/")
	path := "/" + rule.DestBucket + "/" + key
	u := endpoint + encPath(path)

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	host := hostOf(endpoint)
	payloadHash := sha256hex(body)

	hdr := map[string]string{
		"host":                 host,
		"x-amz-date":           amzDate,
		"x-amz-content-sha256": payloadHash,
	}
	if contentType != "" {
		hdr["content-type"] = contentType
	}
	signed := sortedKeys(hdr)
	var ch strings.Builder
	for _, h := range signed {
		ch.WriteString(h + ":" + strings.TrimSpace(hdr[h]) + "\n")
	}
	canonReq := method + "\n" + encPath(path) + "\n\n" + ch.String() + "\n" +
		strings.Join(signed, ";") + "\n" + payloadHash
	scope := dateStamp + "/" + region + "/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256hex([]byte(canonReq))
	sig := hex.EncodeToString(hmacSHA256(sigKey(rule.DestSecretKey, dateStamp, region), sts))

	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential="+rule.DestAccessKey+"/"+scope+
			", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode != 404 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &httpError{resp.StatusCode, string(b)}
	}
	return nil
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string { return "remote replied " + itoa(e.code) + ": " + e.body }

// --- tiny SigV4 / util helpers (self-contained) ------------------------

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}
func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func sigKey(secret, dateStamp, region string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, "s3")
	return hmacSHA256(k, "aws4_request")
}
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
func encPath(p string) string {
	var b strings.Builder
	for _, c := range []byte(p) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~', c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			const hexd = "0123456789ABCDEF"
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&0xf])
		}
	}
	return b.String()
}
func hostOf(endpoint string) string {
	s := endpoint
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
