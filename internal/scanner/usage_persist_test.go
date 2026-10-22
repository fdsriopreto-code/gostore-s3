package scanner

import (
	"testing"

	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/object"
	fsb "github.com/lojadopocket/gostore/internal/object/fs"
)

func TestUsageSnapshotSurvivesRestart(t *testing.T) {
	f, err := fsb.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MakeBucket(ctx(), "photos", object.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	put(t, f, "photos", "a/1.jpg", "xxxxx", 0, object.ObjectOptions{})
	put(t, f, "photos", "a/2.jpg", "yyy", 0, object.ObjectOptions{})
	put(t, f, "photos", "b/3.jpg", "z", 0, object.ObjectOptions{})

	store, _ := bucketcfg.Open(configstore.NewDir(t.TempDir()))

	// First scanner: scan, producing and persisting the usage snapshot.
	s1 := New(f, store, 0)
	s1.ScanOnce(ctx())
	u1 := s1.Usage()
	if u1 == nil || u1.Buckets["photos"].Objects != 3 || u1.Buckets["photos"].Bytes != 9 {
		t.Fatalf("scan usage wrong: %+v", u1)
	}

	// Second scanner over the SAME backend (simulates a restart): usage must
	// be warm immediately, before any scan runs.
	s2 := New(f, store, 0)
	u2 := s2.Usage()
	if u2 == nil {
		t.Fatal("usage snapshot not restored after restart")
	}
	if u2.Buckets["photos"].Objects != 3 || u2.Buckets["photos"].Bytes != 9 {
		t.Fatalf("restored usage wrong: %+v", u2.Buckets)
	}
	if u2.TotalObjects != 3 || u2.TotalBytes != 9 {
		t.Fatalf("restored totals wrong: objs=%d bytes=%d", u2.TotalObjects, u2.TotalBytes)
	}
}
