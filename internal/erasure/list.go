package erasure

import (
	"context"
	"encoding/base64"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lojadopocket/gostore/internal/logger"
	"github.com/lojadopocket/gostore/internal/object"
)

// walkKeysCalls counts full namespace walks; the list cache should keep this
// flat across continuation pages. Test-only signal.
var walkKeysCalls atomic.Int64

// walkKeysMax bounds how many object keys a single namespace walk will
// materialise in memory, so a pathologically large bucket can't OOM the
// process. Listing then works over that (sorted) prefix of the namespace;
// clients should narrow with a prefix. Overridable at startup.
var walkKeysMax = 2_000_000

// SetWalkKeysMax overrides the per-walk key ceiling. Call at startup.
func SetWalkKeysMax(n int) {
	if n > 0 {
		walkKeysMax = n
	}
}

// walkKeys returns every object key in the bucket (slash-separated, sorted).
// An object is any directory that directly contains an xl.meta file. It
// unions the namespace across every online disk so a disk that is missing
// some objects does not hide them from listings or healing.
func (s *Set) walkKeys(ctx context.Context, bucket string) ([]string, error) {
	walkKeysCalls.Add(1)
	found := map[string]struct{}{}
	online := 0
	for _, disk := range s.disks {
		if !disk.IsOnline() {
			continue
		}
		online++
		var capped bool
		var rec func(prefix string) error
		rec = func(prefix string) error {
			if len(found) >= walkKeysMax {
				capped = true
				return nil
			}
			entries, err := disk.ListDir(ctx, bucket, prefix)
			if err != nil {
				return err
			}
			for _, e := range entries {
				if e == metaFile {
					if prefix != "" {
						found[strings.TrimSuffix(prefix, "/")] = struct{}{}
					}
					return nil
				}
			}
			for _, e := range entries {
				if !strings.HasSuffix(e, "/") {
					continue
				}
				if prefix == "" && e == ".gostore.sys/" {
					continue
				}
				if err := rec(path.Join(prefix, e) + "/"); err != nil {
					return err
				}
			}
			return nil
		}
		_ = rec("")
		if capped {
			logger.Warn("erasure: bucket namespace exceeds the walk ceiling; listing is truncated — use a prefix",
				"bucket", bucket, "ceiling", walkKeysMax)
		}
	}
	if online == 0 {
		return nil, ErrReadQuorum
	}
	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

type listParams struct {
	prefix, delimiter, startAfter string
	maxKeys                       int
}

type listPage struct {
	objects     []object.ObjectInfo
	prefixes    []string
	isTruncated bool
	nextMarker  string
}

func (p *Pool) doList(ctx context.Context, bucket string, lp listParams) (listPage, error) {
	if err := p.ensureBucket(ctx, bucket); err != nil {
		return listPage{}, err
	}
	if lp.maxKeys <= 0 || lp.maxKeys > 1000 {
		lp.maxKeys = 1000
	}

	if p.bucketHasVersions(ctx, bucket) {
		lv, err := p.listVersions(ctx, bucket, lp.prefix, lp.delimiter, lp.maxKeys, true)
		if err != nil {
			return listPage{}, err
		}
		var page listPage
		page.isTruncated = lv.IsTruncated
		page.prefixes = lv.Prefixes
		for _, o := range lv.Objects {
			if lp.startAfter != "" && o.Name <= lp.startAfter {
				continue
			}
			page.objects = append(page.objects, o)
			page.nextMarker = o.Name
		}
		return page, nil
	}

	// Objects are spread across sets by key hash — gather from every set.
	// Cached per bucket for a short TTL so continuation pages skip the walk.
	keys, owner, err := p.namespaceKeys(ctx, bucket)
	if err != nil {
		return listPage{}, err
	}

	var page listPage
	seen := map[string]bool{}
	count := 0
	var wantKeys []string // real objects to stat for this page (in order)

	// keys is sorted: binary-search past everything <= startAfter so a deep
	// continuation page doesn't re-scan all the keys before it.
	begin := 0
	if lp.startAfter != "" {
		begin = sort.Search(len(keys), func(i int) bool { return keys[i] > lp.startAfter })
	}

	for _, k := range keys[begin:] {
		if lp.prefix != "" && !strings.HasPrefix(k, lp.prefix) {
			continue
		}
		if lp.delimiter != "" {
			rest := k[len(lp.prefix):]
			if idx := strings.Index(rest, lp.delimiter); idx >= 0 {
				cp := lp.prefix + rest[:idx+len(lp.delimiter)]
				if seen[cp] {
					continue
				}
				if count >= lp.maxKeys {
					page.isTruncated = true
					break
				}
				seen[cp] = true
				page.prefixes = append(page.prefixes, cp)
				page.nextMarker = cp
				count++
				continue
			}
		}
		if count >= lp.maxKeys {
			page.isTruncated = true
			break
		}
		wantKeys = append(wantKeys, k)
		page.nextMarker = k
		count++
	}

	// Stat the page's objects in parallel — one blocking metadata read per
	// key, so a 1000-key page was 1000 sequential round-trips before.
	infos := make([]*object.ObjectInfo, len(wantKeys))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, k := range wantKeys {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, k string) {
			defer wg.Done()
			defer func() { <-sem }()
			if m, err := owner[k].statObject(ctx, bucket, k); err == nil {
				oi := metaToInfo(bucket, k, m)
				infos[i] = &oi
			}
		}(i, k)
	}
	wg.Wait()
	for _, oi := range infos {
		if oi != nil {
			page.objects = append(page.objects, *oi)
		}
	}
	sort.Strings(page.prefixes)
	return page, nil
}

func (p *Pool) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (object.ListObjectsInfo, error) {
	pg, err := p.doList(ctx, bucket, listParams{prefix: prefix, delimiter: delimiter, startAfter: marker, maxKeys: maxKeys})
	if err != nil {
		return object.ListObjectsInfo{}, err
	}
	return object.ListObjectsInfo{
		IsTruncated: pg.isTruncated, NextMarker: pg.nextMarker,
		Objects: pg.objects, Prefixes: pg.prefixes,
	}, nil
}

func (p *Pool) ListObjectsV2(ctx context.Context, bucket, prefix, token, delimiter string, maxKeys int, _ bool, startAfter string) (object.ListObjectsV2Info, error) {
	start := startAfter
	if token != "" {
		if b, err := base64.StdEncoding.DecodeString(token); err == nil {
			start = string(b)
		}
	}
	pg, err := p.doList(ctx, bucket, listParams{prefix: prefix, delimiter: delimiter, startAfter: start, maxKeys: maxKeys})
	if err != nil {
		return object.ListObjectsV2Info{}, err
	}
	out := object.ListObjectsV2Info{
		IsTruncated: pg.isTruncated, ContinuationToken: token,
		Objects: pg.objects, Prefixes: pg.prefixes,
	}
	if pg.isTruncated {
		out.NextContinuationToken = base64.StdEncoding.EncodeToString([]byte(pg.nextMarker))
	}
	return out, nil
}

func (p *Pool) ListObjectVersions(ctx context.Context, bucket, prefix, marker, versionMarker, delimiter string, maxKeys int) (object.ListObjectVersionsInfo, error) {
	if p.bucketHasVersions(ctx, bucket) {
		return p.listVersions(ctx, bucket, prefix, delimiter, maxKeys, false)
	}
	li, err := p.ListObjects(ctx, bucket, prefix, marker, delimiter, maxKeys)
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
