package iam

import (
	"context"
	"testing"
	"time"

	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/iam/policy"
)

func newMgr(t *testing.T) *Manager {
	t.Helper()
	m, err := New("rootadmin", "rootsecret123", configstore.NewDir(t.TempDir()), nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRootAlwaysAllowed(t *testing.T) {
	m := newMgr(t)
	if !m.IsAllowed("rootadmin", policy.Args{Action: "s3:DeleteBucket", BucketName: "x"}) {
		t.Fatal("root must be allowed everything")
	}
	if s, ok := m.LookupSecret("rootadmin"); !ok || s != "rootsecret123" {
		t.Fatal("root secret lookup")
	}
}

func TestUserPolicyEnforced(t *testing.T) {
	m := newMgr(t)
	if err := m.AddUser("alice", "alicesecret", []string{"readonly"}); err != nil {
		t.Fatal(err)
	}
	if !m.IsAllowed("alice", policy.Args{Action: "s3:GetObject", BucketName: "b", ObjectName: "k"}) {
		t.Fatal("alice(readonly) should GET")
	}
	if m.IsAllowed("alice", policy.Args{Action: "s3:PutObject", BucketName: "b", ObjectName: "k"}) {
		t.Fatal("alice(readonly) must not PUT")
	}
	if _, ok := m.LookupSecret("alice"); !ok {
		t.Fatal("alice secret lookup")
	}
	// unknown key
	if m.IsAllowed("mallory", policy.Args{Action: "s3:GetObject", BucketName: "b"}) {
		t.Fatal("unknown key must be denied")
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m1, _ := New("rootadmin", "rootsecret123", configstore.NewDir(dir), nil)
	_ = m1.SetPolicy("teamrw", []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::team-*/*","arn:aws:s3:::team-*"]}]}`))
	if err := m1.AddUser("bob", "bobsecret1", []string{"teamrw"}); err != nil {
		t.Fatal(err)
	}
	_ = m1.AddServiceAccount("bob", "bobsvc0000000000", "bobsvcsecret1", "")

	m2, err := New("rootadmin", "rootsecret123", configstore.NewDir(dir), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m2.LookupSecret("bob"); !ok {
		t.Fatal("bob not persisted")
	}
	if _, ok := m2.LookupSecret("bobsvc0000000000"); !ok {
		t.Fatal("service account not persisted")
	}
	if !m2.IsAllowed("bob", policy.Args{Action: "s3:PutObject", BucketName: "team-x", ObjectName: "f"}) {
		t.Fatal("custom policy not persisted / not enforced")
	}
	if m2.IsAllowed("bob", policy.Args{Action: "s3:PutObject", BucketName: "other", ObjectName: "f"}) {
		t.Fatal("custom policy scope lost")
	}
}

func TestServiceAccountInheritsAndRestricts(t *testing.T) {
	m := newMgr(t)
	_ = m.AddUser("carol", "carolsecret", []string{"readwrite"})
	// svc account restricted to read-only via inline session policy
	inline := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::*"]}]}`
	if err := m.AddServiceAccount("carol", "carolsvc00000000", "carolsvcsecret", inline); err != nil {
		t.Fatal(err)
	}
	if !m.IsAllowed("carolsvc00000000", policy.Args{Action: "s3:GetObject", BucketName: "b", ObjectName: "k"}) {
		t.Fatal("svc should GET (parent allows, inline allows)")
	}
	if m.IsAllowed("carolsvc00000000", policy.Args{Action: "s3:PutObject", BucketName: "b", ObjectName: "k"}) {
		t.Fatal("svc must not PUT (inline restricts)")
	}
}

func TestClusterRefreshPropagates(t *testing.T) {
	be := configstore.NewDir(t.TempDir())
	nodeA, _ := New("rootadmin", "rootsecret123", be, nil)
	nodeB, _ := New("rootadmin", "rootsecret123", be, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	nodeB.StartRefresh(ctx, 50*time.Millisecond)

	if err := nodeA.AddUser("dave", "davesecret1", []string{"readonly"}); err != nil {
		t.Fatal(err)
	}
	// nodeB has not seen it yet.
	if _, ok := nodeB.LookupSecret("dave"); ok {
		t.Fatal("nodeB saw dave before a refresh tick")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := nodeB.LookupSecret("dave"); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("nodeB never picked up dave from the shared store")
}
