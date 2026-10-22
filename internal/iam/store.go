package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lojadopocket/gostore/internal/configstore"
)

// Cipher encrypts/decrypts the IAM blob at rest. *kms.Manager satisfies it
// (AES-256-GCM with the local master key, or Vault Transit). SigV4 needs the
// plaintext secret keys at runtime, so they cannot be hashed — the on-disk
// blob is encrypted instead, and a stray copy of store.json (a backup, a
// filesystem read) is useless without the master key.
type Cipher interface {
	WrapKey([]byte) ([]byte, error)
	UnwrapKey([]byte) ([]byte, error)
}

// encMagic prefixes an encrypted IAM blob. Plaintext (legacy) blobs are JSON,
// which never begins with these bytes, so the two are told apart on read.
var encMagic = []byte("gostore-iam-enc:v1\n")

// persisted is the serialised shape of the IAM database. It is stored as a
// single blob ("iam/store.json") through configstore.Backend — i.e. as an
// object replicated across every disk of every erasure set, so it is
// cluster-wide with no external database. On a single disk the blob lands at
// the same <root>/.gostore.sys/iam/store.json path older builds used.
type persisted struct {
	Users     map[string]userRec    `json:"users"`
	Policies  map[string]string     `json:"policies"` // name -> JSON document
	SvcAccts  map[string]svcAcctRec `json:"serviceAccounts"`
	UpdatedAt time.Time             `json:"updatedAt"`
}

type userRec struct {
	SecretKey string   `json:"secretKey"`
	Policies  []string `json:"policies"`
	Status    string   `json:"status"` // "enabled" | "disabled"
}

type svcAcctRec struct {
	SecretKey    string `json:"secretKey"`
	ParentUser   string `json:"parentUser"`
	InlinePolicy string `json:"inlinePolicy,omitempty"` // JSON document or ""
	Status       string `json:"status"`
}

const storeKey = "iam/store.json"

type store struct {
	be  configstore.Backend
	enc Cipher // nil => store in plaintext (no KMS)
}

func newStore(be configstore.Backend, enc Cipher) *store { return &store{be: be, enc: enc} }

func emptyPersisted() persisted {
	return persisted{
		Users:    map[string]userRec{},
		Policies: map[string]string{},
		SvcAccts: map[string]svcAcctRec{},
	}
}

// loadResult reports how the blob was found so the caller can migrate a
// legacy plaintext store to encrypted form on first boot with a KMS.
type loadResult struct {
	existed   bool // a blob was present (not first run)
	encrypted bool // it was already encrypted at rest
}

func (s *store) load() (persisted, loadResult, error) {
	b, err := s.be.ReadConfig(context.Background(), storeKey)
	if errors.Is(err, configstore.ErrNotFound) {
		return emptyPersisted(), loadResult{}, nil
	}
	if err != nil {
		return persisted{}, loadResult{}, err
	}
	res := loadResult{existed: true}
	if bytes.HasPrefix(b, encMagic) {
		res.encrypted = true
		if s.enc == nil {
			return persisted{}, res, errors.New("iam: store is encrypted at rest but no KMS is configured to decrypt it")
		}
		pt, derr := s.enc.UnwrapKey(b[len(encMagic):])
		if derr != nil {
			return persisted{}, res, fmt.Errorf("iam: decrypt store: %w", derr)
		}
		b = pt
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return emptyPersisted(), res, nil
	}
	if p.Users == nil {
		p.Users = map[string]userRec{}
	}
	if p.Policies == nil {
		p.Policies = map[string]string{}
	}
	if p.SvcAccts == nil {
		p.SvcAccts = map[string]svcAcctRec{}
	}
	return p, res, nil
}

func (s *store) save(p persisted) error {
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = time.Now().UTC()
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if s.enc != nil {
		ct, werr := s.enc.WrapKey(b)
		if werr != nil {
			return fmt.Errorf("iam: encrypt store: %w", werr)
		}
		b = append(append([]byte{}, encMagic...), ct...)
	}
	return s.be.WriteConfig(context.Background(), storeKey, b)
}
