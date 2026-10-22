package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lojadopocket/gostore/internal/erasure"
	"github.com/lojadopocket/gostore/internal/object"
	fsb "github.com/lojadopocket/gostore/internal/object/fs"
	"github.com/lojadopocket/gostore/internal/remotes3"
)

// TestBackupRestoreFromTier proves disaster recovery: with the local store
// empty, restore pulls every object back from the (mock) backup tier.
func TestBackupRestoreFromTier(t *testing.T) {
	// Mock S3 backup tier: a ListObjectsV2 of two objects + their bodies.
	bodies := map[string]string{
		"appbucket/users/1.txt": "hello",
		"appbucket/logs/x.log":  "worldwide",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/remote", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		io.WriteString(w, `<?xml version="1.0"?><ListBucketResult>`+
			`<Contents><Key>appbucket/users/1.txt</Key><Size>5</Size><ETag>"a"</ETag></Contents>`+
			`<Contents><Key>appbucket/logs/x.log</Key><Size>9</Size><ETag>"b"</ETag></Contents>`+
			`<IsTruncated>false</IsTruncated></ListBucketResult>`)
	})
	mux.HandleFunc("/remote/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/remote/")
		if body, ok := bodies[key]; ok {
			io.WriteString(w, body)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	erasure.RegisterTier("restoretest", &remotes3.Client{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "remote", Access: "k", Secret: "s",
	})

	// Local store starts empty.
	backend, err := fsb.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	job := newBackupJob(backend)
	if err := job.setConfig(backupConfig{Enabled: true, Tier: "restoretest"}); err != nil {
		t.Fatal(err)
	}

	job.restore(context_TODO(), false)

	rs := job.restoreStat.Load()
	if rs == nil || rs.Restored != 2 || rs.Errors != 0 {
		t.Fatalf("restore status: %+v (want restored=2 errors=0)", rs)
	}
	// The objects are now in the local store with the right content.
	for key, want := range bodies {
		slash := strings.IndexByte(key, '/')
		bkt, obj := key[:slash], key[slash+1:]
		gr, err := backend.GetObjectNInfo(context_TODO(), bkt, obj, nil, nil, object.ObjectOptions{})
		if err != nil {
			t.Fatalf("restored object missing: %s: %v", key, err)
		}
		b, _ := io.ReadAll(gr)
		gr.Close()
		if string(b) != want {
			t.Fatalf("restored %s content = %q, want %q", key, b, want)
		}
	}
}

func context_TODO() context.Context { return context.Background() }
