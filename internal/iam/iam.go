// Package iam is gostore's identity & access management: users, service
// accounts, named policies, and an authorization check the S3/admin API
// calls on every request. State is JSON replicated across the volume roots
// (see store.go) — no external database.
package iam

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/iam/policy"
	"github.com/lojadopocket/gostore/internal/logger"
)

var (
	ErrNoSuchUser   = errors.New("iam: no such user")
	ErrNoSuchPolicy = errors.New("iam: no such policy")
	ErrUserExists   = errors.New("iam: user already exists")
	ErrInvalidCred  = errors.New("iam: access key or secret key too short")
	ErrIsRoot       = errors.New("iam: cannot modify the root account")
)

// Identity is the resolved principal for an access key.
type Identity struct {
	AccessKey  string
	SecretKey  string
	ParentUser string // set for service accounts / STS
	IsRoot     bool
	Policies   []string       // named policies in effect
	Inline     *policy.Policy // session/inline policy (intersection semantics)
	Bound      *policy.Policy // hard ceiling carried from the issuing identity
	Expiry     time.Time      // zero == no expiry
}

// Manager is the in-memory IAM state with write-through persistence.
type Manager struct {
	mu sync.RWMutex

	rootAccess string
	rootSecret string

	users    map[string]userRec
	svcAccts map[string]svcAcctRec
	custom   map[string]*policy.Policy // custom named policies
	builtin  map[string]*policy.Policy

	sts   map[string]stsRec // in-memory only (M9)
	store *store

	// inlineCache memoises the parsed form of each service account's inline
	// policy so Identity() (called on every authenticated request) doesn't
	// re-unmarshal it. Keyed by access key; the raw text is compared so an
	// updated inline policy is picked up automatically.
	inlineMu    sync.RWMutex
	inlineCache map[string]inlineCompiled

	// lastSync is the UpdatedAt stamp of the persisted blob we last wrote or
	// loaded; the background refresher only re-applies a newer one.
	lastSync time.Time
}

type stsRec struct {
	secret     string
	parentUser string
	pol        *policy.Policy // session policy supplied to AssumeRole (optional)
	bound      *policy.Policy // ceiling inherited from the issuing identity
	expiry     time.Time
}

type inlineCompiled struct {
	raw string
	pol *policy.Policy
}

// compileInline returns the parsed inline policy for accessKey, parsing and
// caching on a miss or when doc changed. Returns nil if doc is empty or bad.
func (m *Manager) compileInline(accessKey, doc string) *policy.Policy {
	if doc == "" {
		return nil
	}
	m.inlineMu.RLock()
	e, hit := m.inlineCache[accessKey]
	m.inlineMu.RUnlock()
	if hit && e.raw == doc {
		return e.pol
	}
	p, err := policy.Parse([]byte(doc))
	if err != nil {
		p = nil
	}
	m.inlineMu.Lock()
	if m.inlineCache == nil {
		m.inlineCache = map[string]inlineCompiled{}
	}
	m.inlineCache[accessKey] = inlineCompiled{raw: doc, pol: p}
	m.inlineMu.Unlock()
	return p
}

// New builds a Manager with the given root credential, persisting through the
// configstore backend (an object replicated across the cluster).
func New(rootAccess, rootSecret string, be configstore.Backend) (*Manager, error) {
	m := &Manager{
		rootAccess:  rootAccess,
		rootSecret:  rootSecret,
		users:       map[string]userRec{},
		svcAccts:    map[string]svcAcctRec{},
		custom:      map[string]*policy.Policy{},
		builtin:     policy.Builtin(),
		sts:         map[string]stsRec{},
		store:       newStore(be),
		inlineCache: map[string]inlineCompiled{},
	}
	p, err := m.store.load()
	if err != nil {
		return nil, err
	}
	m.applyPersisted(p)
	return m, nil
}

// applyPersisted replaces the in-memory user/svcacct/custom-policy state with
// the contents of p. Caller must hold m.mu (or be in New before it's shared).
func (m *Manager) applyPersisted(p persisted) {
	m.users = map[string]userRec{}
	m.svcAccts = map[string]svcAcctRec{}
	m.custom = map[string]*policy.Policy{}
	for k, v := range p.Users {
		m.users[k] = v
	}
	for k, v := range p.SvcAccts {
		m.svcAccts[k] = v
	}
	for name, doc := range p.Policies {
		pol, err := policy.Parse([]byte(doc))
		if err != nil {
			continue
		}
		m.custom[name] = pol
	}
	m.lastSync = p.UpdatedAt
}

// StartRefresh polls the backing store on an interval and re-applies any
// version newer than the one this node last wrote — this is how a user
// created on one cluster node becomes visible on the others.
func (m *Manager) StartRefresh(ctx context.Context, interval time.Duration) {
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
				p, err := m.store.load()
				if err != nil {
					continue
				}
				m.mu.Lock()
				if p.UpdatedAt.After(m.lastSync) {
					m.applyPersisted(p)
					logger.Debug("iam: applied newer state from store", "updatedAt", p.UpdatedAt)
				}
				m.mu.Unlock()
			}
		}
	}()
}

func (m *Manager) flush() error {
	p := persisted{
		Users:    map[string]userRec{},
		Policies: map[string]string{},
		SvcAccts: map[string]svcAcctRec{},
	}
	for k, v := range m.users {
		p.Users[k] = v
	}
	for k, v := range m.svcAccts {
		p.SvcAccts[k] = v
	}
	for name, pol := range m.custom {
		b, err := pol.MarshalJSON()
		if err == nil {
			p.Policies[name] = string(b)
		}
	}
	p.UpdatedAt = time.Now().UTC()
	if err := m.store.save(p); err != nil {
		return err
	}
	m.lastSync = p.UpdatedAt
	return nil
}

// --- credential lookup (used by auth) --------------------------------

// LookupSecret returns the secret key for an access key.
func (m *Manager) LookupSecret(accessKey string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if accessKey == m.rootAccess {
		return m.rootSecret, true
	}
	if u, ok := m.users[accessKey]; ok && u.Status != "disabled" {
		return u.SecretKey, true
	}
	if s, ok := m.svcAccts[accessKey]; ok && s.Status != "disabled" {
		return s.SecretKey, true
	}
	if s, ok := m.sts[accessKey]; ok {
		if time.Now().Before(s.expiry) {
			return s.secret, true
		}
	}
	return "", false
}

// Identity resolves an access key to its principal + effective policy.
func (m *Manager) Identity(accessKey string) (*Identity, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if accessKey == m.rootAccess {
		return &Identity{AccessKey: accessKey, SecretKey: m.rootSecret, IsRoot: true}, true
	}
	if u, ok := m.users[accessKey]; ok {
		return &Identity{AccessKey: accessKey, SecretKey: u.SecretKey, Policies: u.Policies}, true
	}
	if s, ok := m.svcAccts[accessKey]; ok {
		id := &Identity{AccessKey: accessKey, SecretKey: s.SecretKey, ParentUser: s.ParentUser}
		if pu, ok := m.users[s.ParentUser]; ok {
			id.Policies = pu.Policies
		} else if s.ParentUser == m.rootAccess {
			id.IsRoot = true
		}
		id.Inline = m.compileInline(accessKey, s.InlinePolicy)
		return id, true
	}
	if s, ok := m.sts[accessKey]; ok && time.Now().Before(s.expiry) {
		id := &Identity{AccessKey: accessKey, SecretKey: s.secret, ParentUser: s.parentUser, Inline: s.pol, Bound: s.bound, Expiry: s.expiry}
		if pu, ok := m.users[s.parentUser]; ok {
			id.Policies = pu.Policies
		} else if s.parentUser == m.rootAccess {
			id.IsRoot = true
		}
		return id, true
	}
	return nil, false
}

// IsAllowed evaluates an authorization request for an access key.
func (m *Manager) IsAllowed(accessKey string, args policy.Args) bool {
	id, ok := m.Identity(accessKey)
	if !ok {
		return false
	}
	args.AccountName = accessKey
	if id.IsRoot && id.Inline == nil && id.Bound == nil {
		return true
	}
	// Inline (session) policy must allow, if present.
	if id.Inline != nil && !id.Inline.IsAllowed(args) {
		return false
	}
	// Bound is the ceiling inherited from the identity that issued this
	// credential (e.g. the inline policy of the service account that called
	// AssumeRole). It must allow too — a temporary credential can never grant
	// more than the identity that minted it, even when the parent is root.
	if id.Bound != nil && !id.Bound.IsAllowed(args) {
		return false
	}
	if id.IsRoot {
		return true // inline + bound already checked
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, name := range id.Policies {
		if pol := m.resolveLocked(name); pol != nil && pol.IsAllowed(args) {
			return true
		}
	}
	return false
}

func (m *Manager) resolveLocked(name string) *policy.Policy {
	if p, ok := m.custom[name]; ok {
		return p
	}
	if p, ok := m.builtin[name]; ok {
		return p
	}
	return nil
}

// --- user management -----------------------------------------------

// UserInfo is the public view of a user.
type UserInfo struct {
	AccessKey string   `json:"accessKey"`
	Policies  []string `json:"policies"`
	Status    string   `json:"status"`
}

func (m *Manager) AddUser(accessKey, secretKey string, policies []string) error {
	if len(accessKey) < 3 || len(secretKey) < 8 {
		return ErrInvalidCred
	}
	if accessKey == m.rootAccess {
		return ErrIsRoot
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range policies {
		if m.resolveLocked(p) == nil {
			return ErrNoSuchPolicy
		}
	}
	m.users[accessKey] = userRec{SecretKey: secretKey, Policies: policies, Status: "enabled"}
	return m.flush()
}

func (m *Manager) RemoveUser(accessKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[accessKey]; !ok {
		return ErrNoSuchUser
	}
	delete(m.users, accessKey)
	for k, s := range m.svcAccts {
		if s.ParentUser == accessKey {
			delete(m.svcAccts, k)
		}
	}
	return m.flush()
}

// SetUserSecret replaces a user's secret key (key rotation). The access key
// stays the same; the old secret stops working immediately.
func (m *Manager) SetUserSecret(accessKey, newSecret string) error {
	if len(newSecret) < 8 {
		return ErrInvalidCred
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[accessKey]
	if !ok {
		return ErrNoSuchUser
	}
	u.SecretKey = newSecret
	m.users[accessKey] = u
	return m.flush()
}

func (m *Manager) SetUserStatus(accessKey, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[accessKey]
	if !ok {
		return ErrNoSuchUser
	}
	if status != "enabled" && status != "disabled" {
		status = "enabled"
	}
	u.Status = status
	m.users[accessKey] = u
	return m.flush()
}

func (m *Manager) ListUsers() []UserInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]UserInfo, 0, len(m.users))
	for k, u := range m.users {
		out = append(out, UserInfo{AccessKey: k, Policies: u.Policies, Status: u.Status})
	}
	return out
}

// --- policy management -------------------------------------------

func (m *Manager) SetPolicy(name string, doc []byte) error {
	if name == "" || strings.ContainsAny(name, "/\\ ") {
		return errors.New("iam: invalid policy name")
	}
	pol, err := policy.Parse(doc)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.custom[name] = pol
	return m.flush()
}

func (m *Manager) RemovePolicy(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.custom[name]; !ok {
		return ErrNoSuchPolicy
	}
	delete(m.custom, name)
	return m.flush()
}

// PolicyDoc is a named policy document.
type PolicyDoc struct {
	Name     string          `json:"name"`
	Builtin  bool            `json:"builtin"`
	Document json.RawMessage `json:"document"`
}

func (m *Manager) ListPolicies() []PolicyDoc {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []PolicyDoc
	for name, p := range m.builtin {
		b, _ := p.MarshalJSON()
		out = append(out, PolicyDoc{Name: name, Builtin: true, Document: b})
	}
	for name, p := range m.custom {
		b, _ := p.MarshalJSON()
		out = append(out, PolicyDoc{Name: name, Document: b})
	}
	return out
}

// --- service accounts ----------------------------------------

func (m *Manager) AddServiceAccount(parentUser, accessKey, secretKey, inlineDoc string) error {
	if len(accessKey) < 3 || len(secretKey) < 8 {
		return ErrInvalidCred
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if parentUser != m.rootAccess {
		if _, ok := m.users[parentUser]; !ok {
			return ErrNoSuchUser
		}
	}
	if inlineDoc != "" {
		if _, err := policy.Parse([]byte(inlineDoc)); err != nil {
			return err
		}
	}
	m.svcAccts[accessKey] = svcAcctRec{
		SecretKey: secretKey, ParentUser: parentUser, InlinePolicy: inlineDoc, Status: "enabled",
	}
	return m.flush()
}

func (m *Manager) RemoveServiceAccount(accessKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.svcAccts[accessKey]; !ok {
		return ErrNoSuchUser
	}
	delete(m.svcAccts, accessKey)
	return m.flush()
}

// SvcAcctInfo is the public view of a service account.
type SvcAcctInfo struct {
	AccessKey  string `json:"accessKey"`
	ParentUser string `json:"parentUser"`
	Status     string `json:"status"`
}

func (m *Manager) ListServiceAccounts(parentUser string) []SvcAcctInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []SvcAcctInfo
	for k, s := range m.svcAccts {
		if parentUser != "" && s.ParentUser != parentUser {
			continue
		}
		out = append(out, SvcAcctInfo{AccessKey: k, ParentUser: s.ParentUser, Status: s.Status})
	}
	return out
}

// --- STS (M9) ------------------------------------------------

// AddSTS registers a temporary credential in memory. pol is the optional
// session policy supplied to AssumeRole; bound is the ceiling inherited from
// the caller (e.g. a service account's inline policy) and is enforced in
// addition to the parent's named policies so STS can never escalate.
func (m *Manager) AddSTS(accessKey, secretKey, parentUser string, pol, bound *policy.Policy, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sts[accessKey] = stsRec{secret: secretKey, parentUser: parentUser, pol: pol, bound: bound, expiry: time.Now().Add(ttl)}
}

// RootAccessKey returns the configured root access key.
func (m *Manager) RootAccessKey() string { return m.rootAccess }
