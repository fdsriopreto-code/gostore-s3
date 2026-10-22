package replication

import (
	"context"
	"strings"
	"testing"

	"github.com/lojadopocket/gostore/internal/bucketcfg"
	"github.com/lojadopocket/gostore/internal/object"
	fsb "github.com/lojadopocket/gostore/internal/object/fs"
)

func ctx() context.Context { return context.Background() }

func putStr(t *testing.T, f *fsb.FS, bucket, key, body string) {
	t.Helper()
	pr := object.NewPutObjReader(strings.NewReader(body), int64(len(body)), int64(len(body)))
	if _, err := f.PutObject(ctx(), bucket, key, pr, object.ObjectOptions{
		UserDefined: map[string]string{"content-type": "text/plain"},
	}); err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
}

func TestDurableQueueSurvivesRestartAndRetries(t *testing.T) {
	f, err := fsb.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MakeBucket(ctx(), "src", object.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	putStr(t, f, "src", "k/obj.txt", "payload-123")

	bc, _ := bucketcfg.Open(f)
	_ = bc.Update("src", func(c *bucketcfg.Config) {
		c.Replication = []bucketcfg.ReplicationRule{{ID: "r1", DestBucket: "dst"}}
	})

	// Manager #1: enqueue, drain -> fails (dst missing), event persists.
	m1 := New(bc, f)
	m1.Publish(Event{Op: Put, Bucket: "src", Key: "k/obj.txt"})
	m1.DrainOnce(ctx())
	if m1.Pending() != 1 {
		t.Fatalf("after failed drain, want 1 pending, got %d", m1.Pending())
	}

	// Manager #2 over the same backend (simulated restart): queue reloaded.
	m2 := New(bc, f)
	if m2.Pending() != 1 {
		t.Fatalf("durable queue not reloaded after restart: pending=%d", m2.Pending())
	}

	// Create the destination; re-publish to reset backoff, then drain.
	if err := f.MakeBucket(ctx(), "dst", object.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	m2.Publish(Event{Op: Put, Bucket: "src", Key: "k/obj.txt"})
	m2.DrainOnce(ctx())
	if m2.Pending() != 0 {
		t.Fatalf("after dst exists, queue should drain to 0, got %d", m2.Pending())
	}

	oi, err := f.GetObjectInfo(ctx(), "dst", "k/obj.txt", object.ObjectOptions{})
	if err != nil {
		t.Fatalf("replicated object missing in dst: %v", err)
	}
	if oi.Size != int64(len("payload-123")) {
		t.Fatalf("replicated object wrong size: %d", oi.Size)
	}

	// A fresh Manager sees an empty persisted queue.
	m3 := New(bc, f)
	if m3.Pending() != 0 {
		t.Fatalf("persisted queue should be empty after success, got %d", m3.Pending())
	}
}

func TestBackfillEnqueuesExistingObjects(t *testing.T) {
	f, err := fsb.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.MakeBucket(ctx(), "src", object.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := f.MakeBucket(ctx(), "dst", object.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	// Objects written BEFORE the rule exists — replication would never see them.
	for _, k := range []string{"a/1.txt", "a/2.txt", "b/3.txt"} {
		putStr(t, f, "src", k, "data-"+k)
	}

	bc, _ := bucketcfg.Open(f)
	_ = bc.Update("src", func(c *bucketcfg.Config) {
		c.Replication = []bucketcfg.ReplicationRule{{ID: "r1", DestBucket: "dst"}}
	})

	m := New(bc, f)
	n, err := m.Backfill(ctx(), "src")
	if err != nil || n != 3 {
		t.Fatalf("Backfill: n=%d err=%v (want 3)", n, err)
	}
	m.DrainOnce(ctx())
	if m.Pending() != 0 {
		t.Fatalf("queue not drained: %d pending", m.Pending())
	}
	// All three now exist in the destination.
	for _, k := range []string{"a/1.txt", "a/2.txt", "b/3.txt"} {
		if _, err := f.GetObjectInfo(ctx(), "dst", k, object.ObjectOptions{}); err != nil {
			t.Fatalf("backfilled object missing in dst: %s: %v", k, err)
		}
	}
}
