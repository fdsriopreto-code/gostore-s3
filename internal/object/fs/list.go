package fs

import (
	"context"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lojadopocket/gostore/internal/object"
)

// walkKeys returns the object keys of a bucket under prefix, slash-separated
// and sorted in byte order (matching S3 listing order). When the prefix names
// a directory boundary (contains a "/"), the walk starts at that subtree
// instead of the whole bucket, so listing e.g. "avatars/user_123/" reads only
// that folder rather than every object in the bucket — the single biggest
// listing cost on a large, deeply-nested bucket. An empty prefix walks the
// whole bucket as before.
func (f *FS) walkKeys(bucket, prefix string) ([]string, error) {
	root := f.bucketDir(bucket)
	base := root
	if dir := prefixWalkDir(prefix); dir != "" {
		base = filepath.Join(root, filepath.FromSlash(dir))
	}
	// The scoped base may not exist (no object under that prefix) — that is an
	// empty listing, not an error.
	if _, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var keys []string
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if prefix != "" && !strings.HasPrefix(rel, prefix) {
			return nil
		}
		keys = append(keys, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	return keys, nil
}

// prefixWalkDir returns the directory boundary of a listing prefix — the part
// up to and including the last "/". "avatars/user_1/p" -> "avatars/user_1/",
// "avatars/" -> "avatars/", "ab" (no "/") -> "" (walk the whole bucket).
func prefixWalkDir(prefix string) string {
	if i := strings.LastIndexByte(prefix, '/'); i >= 0 {
		return prefix[:i+1]
	}
	return ""
}

type listParams struct {
	prefix, delimiter string
	startAfter        string // exclusive lower bound
	maxKeys           int
}

type listPage struct {
	objects     []object.ObjectInfo
	prefixes    []string
	isTruncated bool
	nextMarker  string
}

// bucketHasVersions reports whether the bucket has a non-empty version store,
// in which case listings must come from the version log.
func (f *FS) bucketHasVersions(bucket string) bool {
	ents, err := os.ReadDir(filepath.Join(f.root, sysDir, "objver", bucket))
	return err == nil && len(ents) > 0
}

func (f *FS) doList(bucket string, p listParams) (listPage, error) {
	if err := f.ensureBucket(bucket); err != nil {
		return listPage{}, err
	}
	if p.maxKeys <= 0 {
		p.maxKeys = 1000
	}
	if p.maxKeys > 1000 {
		p.maxKeys = 1000
	}

	if f.bucketHasVersions(bucket) {
		lv, err := f.listVersioned(bucket, p.prefix, p.delimiter, p.maxKeys, true)
		if err != nil {
			return listPage{}, err
		}
		var page listPage
		page.isTruncated = lv.IsTruncated
		page.prefixes = lv.Prefixes
		for _, o := range lv.Objects {
			if p.startAfter != "" && o.Name <= p.startAfter {
				continue
			}
			page.objects = append(page.objects, o)
			page.nextMarker = o.Name
		}
		return page, nil
	}

	keys, err := f.walkKeys(bucket, p.prefix)
	if err != nil {
		return listPage{}, err
	}

	var page listPage
	seenPrefix := map[string]bool{}
	count := 0

	// keys is sorted, so jump straight past everything <= startAfter instead
	// of scanning from the front on every (continuation) page — deep
	// pagination was O(position) per page, now O(log n + pageSize).
	begin := 0
	if p.startAfter != "" {
		begin = sort.Search(len(keys), func(i int) bool { return keys[i] > p.startAfter })
	}

	for _, k := range keys[begin:] {
		if p.prefix != "" && !strings.HasPrefix(k, p.prefix) {
			continue
		}

		if p.delimiter != "" {
			rest := k[len(p.prefix):]
			if idx := strings.Index(rest, p.delimiter); idx >= 0 {
				cp := p.prefix + rest[:idx+len(p.delimiter)]
				if seenPrefix[cp] {
					continue
				}
				if count >= p.maxKeys {
					page.isTruncated = true
					page.nextMarker = lastMarker(page)
					return page, nil
				}
				seenPrefix[cp] = true
				page.prefixes = append(page.prefixes, cp)
				page.nextMarker = cp
				count++
				continue
			}
		}

		if count >= p.maxKeys {
			page.isTruncated = true
			page.nextMarker = lastMarker(page)
			return page, nil
		}
		oi, gerr := f.getInfoUnlocked(bucket, k)
		if gerr != nil {
			if os.IsNotExist(gerr) {
				continue
			}
			return listPage{}, gerr
		}
		page.objects = append(page.objects, oi)
		page.nextMarker = k
		count++
	}
	sort.Strings(page.prefixes)
	return page, nil
}

func lastMarker(p listPage) string {
	last := ""
	if n := len(p.objects); n > 0 {
		last = p.objects[n-1].Name
	}
	if n := len(p.prefixes); n > 0 && p.prefixes[n-1] > last {
		last = p.prefixes[n-1]
	}
	return last
}

func encodeToken(s string) string {
	if s == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func decodeToken(s string) string {
	if s == "" {
		return ""
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s // tolerate a raw key as token
	}
	return string(b)
}

func (f *FS) ListObjects(_ context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (object.ListObjectsInfo, error) {
	page, err := f.doList(bucket, listParams{
		prefix: prefix, delimiter: delimiter, startAfter: marker, maxKeys: maxKeys,
	})
	if err != nil {
		return object.ListObjectsInfo{}, err
	}
	return object.ListObjectsInfo{
		IsTruncated: page.isTruncated,
		NextMarker:  page.nextMarker,
		Objects:     page.objects,
		Prefixes:    page.prefixes,
	}, nil
}

func (f *FS) ListObjectsV2(_ context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int, _ bool, startAfter string) (object.ListObjectsV2Info, error) {
	start := startAfter
	if continuationToken != "" {
		start = decodeToken(continuationToken)
	}
	page, err := f.doList(bucket, listParams{
		prefix: prefix, delimiter: delimiter, startAfter: start, maxKeys: maxKeys,
	})
	if err != nil {
		return object.ListObjectsV2Info{}, err
	}
	out := object.ListObjectsV2Info{
		IsTruncated:       page.isTruncated,
		ContinuationToken: continuationToken,
		Objects:           page.objects,
		Prefixes:          page.prefixes,
	}
	if page.isTruncated {
		out.NextContinuationToken = encodeToken(page.nextMarker)
	}
	return out, nil
}

func (f *FS) ListObjectVersions(_ context.Context, bucket, prefix, marker, versionMarker, delimiter string, maxKeys int) (object.ListObjectVersionsInfo, error) {
	if f.bucketHasVersions(bucket) {
		return f.listVersioned(bucket, prefix, delimiter, maxKeys, false)
	}
	// Unversioned bucket: every object is its sole "null" version.
	li, err := f.ListObjects(context.Background(), bucket, prefix, marker, delimiter, maxKeys)
	if err != nil {
		return object.ListObjectVersionsInfo{}, err
	}
	for i := range li.Objects {
		li.Objects[i].VersionID = "null"
		li.Objects[i].IsLatest = true
	}
	return object.ListObjectVersionsInfo{
		IsTruncated: li.IsTruncated, NextMarker: li.NextMarker,
		Objects: li.Objects, Prefixes: li.Prefixes,
	}, nil
}
