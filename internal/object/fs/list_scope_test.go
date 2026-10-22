package fs

import (
	"fmt"
	"sort"
	"testing"

	"github.com/lojadopocket/gostore/internal/object"
)

// listAll drains ListObjectsV2 across all continuation pages (no delimiter)
// and returns the keys in order, proving pagination has no gaps/dupes.
func listAllV2(t *testing.T, f *FS, bucket, prefix string, pageSize int) []string {
	t.Helper()
	var out []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 100000 {
			t.Fatal("pagination did not terminate")
		}
		res, err := f.ListObjectsV2(ctx(), bucket, prefix, token, "", pageSize, false, "")
		if err != nil {
			t.Fatalf("ListObjectsV2: %v", err)
		}
		for _, o := range res.Objects {
			out = append(out, o.Name)
		}
		if !res.IsTruncated {
			break
		}
		token = res.NextContinuationToken
		if token == "" {
			t.Fatal("truncated but empty continuation token")
		}
	}
	return out
}

func TestListPrefixScopeAndPagination(t *testing.T) {
	f := newTestFS(t)
	if err := f.MakeBucket(ctx(), "data", object.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}

	// Build a realistic, deeply-nested namespace.
	var all []string
	for u := 0; u < 12; u++ {
		for i := 0; i < 20; i++ {
			k := fmt.Sprintf("avatars/user_%d/photo_%03d.jpg", u, i)
			putString(t, f, "data", k, "x")
			all = append(all, k)
		}
	}
	// Decoy keys that share a prefix boundary (user_1 vs user_10..).
	for i := 0; i < 5; i++ {
		k := fmt.Sprintf("avatars/user_1extra/f_%d.bin", i)
		putString(t, f, "data", k, "x")
		all = append(all, k)
	}
	// Unrelated top-level keys.
	for i := 0; i < 8; i++ {
		k := fmt.Sprintf("logs/2026/day_%d.log", i)
		putString(t, f, "data", k, "x")
		all = append(all, k)
	}
	sort.Strings(all)

	// 1) Full listing across tiny pages == every key exactly once, in order.
	got := listAllV2(t, f, "data", "", 7)
	if !equal(got, all) {
		t.Fatalf("full paginated list mismatch:\n got %d keys\n want %d keys\n first diff near %v",
			len(got), len(all), firstDiff(got, all))
	}

	// 2) Prefix "avatars/user_1/" must return exactly that user's 20 photos,
	//    NOT user_10, user_11, or user_1extra.
	want1 := filterPrefix(all, "avatars/user_1/")
	gotP := listAllV2(t, f, "data", "avatars/user_1/", 5)
	if !equal(gotP, want1) {
		t.Fatalf("prefix scope wrong: got %d want %d\n got=%v", len(gotP), len(want1), gotP)
	}

	// 3) Partial-segment prefix "avatars/user_1" (no slash) matches user_1,
	//    user_10, user_11, user_1extra — classic S3 prefix semantics.
	wantPart := filterPrefix(all, "avatars/user_1")
	gotPart := listAllV2(t, f, "data", "avatars/user_1", 9)
	if !equal(gotPart, wantPart) {
		t.Fatalf("partial prefix wrong: got %d want %d", len(gotPart), len(wantPart))
	}

	// 4) Non-existent prefix -> empty, no error.
	if g := listAllV2(t, f, "data", "nope/nothing/", 10); len(g) != 0 {
		t.Fatalf("empty prefix should list nothing, got %d", len(g))
	}

	// 5) Delimiter folder view at root -> top-level common prefixes.
	res, err := f.ListObjectsV2(ctx(), "data", "", "", "/", 1000, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if !equal(res.Prefixes, []string{"avatars/", "logs/"}) {
		t.Fatalf("delimiter root prefixes wrong: %v", res.Prefixes)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func filterPrefix(all []string, pfx string) []string {
	var out []string
	for _, k := range all {
		if len(k) >= len(pfx) && k[:len(pfx)] == pfx {
			out = append(out, k)
		}
	}
	return out
}
func firstDiff(a, b []string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("idx %d: got %q want %q", i, a[i], b[i])
		}
	}
	return "length differs"
}
