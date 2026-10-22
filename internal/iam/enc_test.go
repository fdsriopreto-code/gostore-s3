package iam

import (
	"bytes"
	"context"
	"testing"

	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/kms"
)

func TestIAMStoreEncryptionAtRest(t *testing.T) {
	ctx := context.Background()
	be := configstore.NewDir(t.TempDir())
	km, err := kms.New([]string{t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	// Create with a cipher and add a user with a recognizable secret.
	m, err := New("root", "rootsecret123", be, km)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.AddUser("alice", "alicesecret123", nil); err != nil {
		t.Fatal(err)
	}

	// On-disk blob must be encrypted and must NOT contain the secret.
	raw, err := be.ReadConfig(ctx, storeKey)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if !bytes.HasPrefix(raw, encMagic) {
		t.Fatal("store is not encrypted at rest")
	}
	if bytes.Contains(raw, []byte("alicesecret123")) {
		t.Fatal("secret key found in plaintext on disk")
	}

	// Reload with the cipher: the secret round-trips.
	m2, err := New("root", "rootsecret123", be, km)
	if err != nil {
		t.Fatal(err)
	}
	if sec, ok := m2.LookupSecret("alice"); !ok || sec != "alicesecret123" {
		t.Fatalf("secret not recovered after reload: ok=%v sec=%q", ok, sec)
	}

	// An encrypted store with no KMS must fail loudly, not silently wipe IAM.
	if _, err := New("root", "rootsecret123", be, nil); err == nil {
		t.Fatal("expected error loading encrypted store without a cipher")
	}
}

func TestIAMStorePlaintextMigratesOnBoot(t *testing.T) {
	ctx := context.Background()
	be := configstore.NewDir(t.TempDir())
	km, err := kms.New([]string{t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	// Legacy: write a plaintext store (no cipher), as older builds did.
	mp, err := New("root", "rootsecret123", be, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mp.AddUser("bob", "bobsecret12345", nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := be.ReadConfig(ctx, storeKey)
	if bytes.HasPrefix(raw, encMagic) {
		t.Fatal("plaintext store unexpectedly encrypted")
	}

	// Boot WITH a KMS: the legacy store is migrated to encrypted-at-rest,
	// and existing credentials keep working.
	m, err := New("root", "rootsecret123", be, km)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := be.ReadConfig(ctx, storeKey)
	if !bytes.HasPrefix(raw2, encMagic) {
		t.Fatal("legacy plaintext store was not migrated to encrypted")
	}
	if sec, ok := m.LookupSecret("bob"); !ok || sec != "bobsecret12345" {
		t.Fatalf("secret lost across migration: ok=%v sec=%q", ok, sec)
	}
}
