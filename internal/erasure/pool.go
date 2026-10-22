package erasure

import (
	"context"
	"errors"
	"hash/fnv"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lojadopocket/gostore/internal/configstore"
	"github.com/lojadopocket/gostore/internal/nslock"
	"github.com/lojadopocket/gostore/internal/object"
	"github.com/lojadopocket/gostore/internal/storage"
)

// Pool is an object.Layer backed by one or more erasure sets. M4 runs a
// single set; M5 adds multiple sets with key-hashed placement.
type Pool struct {
	sets   []*Set
	kms    kmsWrapper
	locker func(bucket string, objects ...string) object.RWLocker
	mrf    *mrfQueue
	lcache *listCache
	ns     *nslock.Striped

	bmu       sync.Mutex
	bucketsOK map[string]time.Time // bucket -> last confirmed to exist

	// pool layout: set indices that are being decommissioned. When empty
	// (the common case) hasInactive is false and set placement is the plain
	// hash over every set — zero extra cost. See decommission.go.
	layoutMu    sync.RWMutex
	draining    map[int]bool
	hasInactive atomic.Bool
	cfgStore    configstore.Backend
	decomMu     sync.Mutex // one decommission / rebalance at a time
	progMu      sync.Mutex // guards decom
	decom       decomProgress
}

var _ object.Layer = (*Pool)(nil)

// NewPool builds a pool from erasure sets.
func NewPool(sets ...*Set) (*Pool, error) {
	if len(sets) == 0 {
		return nil, errors.New("erasure: no sets")
	}
	return &Pool{sets: sets, ns: nslock.New(), lcache: newListCache(), bucketsOK: map[string]time.Time{}}, nil
}

// FromDisks is the common case: build a single set (and pool) from n disks.
func FromDisks(disks []Disk) (*Pool, error) {
	set, err := NewSet(disks)
	if err != nil {
		return nil, err
	}
	return NewPool(set)
}

func keyHash(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return h.Sum32()
}

// setFor returns the write target for a key: the plain hash over every set,
// unless a decommission is in progress, in which case draining sets are
// excluded so new writes land only on sets that will remain.
func (p *Pool) setFor(key string) *Set {
	if len(p.sets) == 1 {
		return p.sets[0]
	}
	if p.hasInactive.Load() {
		if act := p.activeSets(); len(act) > 0 {
			return act[int(keyHash(key))%len(act)]
		}
	}
	return p.sets[int(keyHash(key))%len(p.sets)]
}

// --- lifecycle / introspection ---------------------------------------

func (p *Pool) Shutdown(ctx context.Context) error {
	if p.mrf != nil {
		p.mrf.flush(ctx) // persist any pending self-heal work
	}
	WaitConfigRepair() // let async config read-repairs finish their disk writes
	return nil
}

func (p *Pool) StorageInfo(ctx context.Context) (object.StorageInfo, []error) {
	var si object.StorageInfo
	si.Backend.Type = "erasure"
	si.Backend.StandardSCParity = p.sets[0].parityBlocks
	for _, set := range p.sets {
		for _, d := range set.disks {
			di, err := d.DiskInfo(ctx)
			state := "ok"
			if err != nil || !d.IsOnline() {
				state = "offline"
			}
			si.Disks = append(si.Disks, object.DiskMetrics{
				Endpoint: d.String(), State: state,
				TotalSpace: di.Total, FreeSpace: di.Free, UsedSpace: di.Used,
				DiskIndex: d.Index(),
			})
		}
	}
	return si, nil
}

func (p *Pool) Health(ctx context.Context, _ object.HealthOptions) object.HealthResult {
	for _, set := range p.sets {
		online := 0
		for _, d := range set.disks {
			if d.IsOnline() {
				online++
			}
		}
		if online < set.writeQuorum() {
			return object.HealthResult{
				Healthy: false, WriteQuorum: set.writeQuorum(),
				Reason: "not enough disks online for write quorum",
			}
		}
	}
	return object.HealthResult{Healthy: true, WriteQuorum: p.sets[0].writeQuorum()}
}

// SetLocker installs a distributed namespace-lock factory (cluster mode).
// When set it replaces the process-local RWMutex locks.
func (p *Pool) SetLocker(fn func(bucket string, objects ...string) object.RWLocker) {
	p.locker = fn
}

func (p *Pool) NewNSLock(bucket string, objects ...string) object.RWLocker {
	if p.locker != nil {
		return p.locker(bucket, objects...)
	}
	return p.ns.For(bucket, objects...)
}

// --- buckets --------------------------------------------------------

func (p *Pool) MakeBucket(ctx context.Context, bucket string, _ object.MakeBucketOptions) error {
	if !validBucketName(bucket) {
		return object.ErrBucketNameInvalid
	}
	for _, set := range p.sets {
		if err := set.MakeBucket(ctx, bucket); err != nil {
			if errors.Is(err, storage.ErrVolumeExists) {
				return object.BucketExists{Bucket: bucket}
			}
			return err
		}
	}
	p.bmu.Lock()
	p.bucketsOK[bucket] = time.Now()
	p.bmu.Unlock()
	return nil
}

func (p *Pool) GetBucketInfo(ctx context.Context, bucket string) (object.BucketInfo, error) {
	vi, err := p.sets[0].StatBucket(ctx, bucket)
	if err != nil {
		return object.BucketInfo{}, object.BucketNotFound{Bucket: bucket}
	}
	return object.BucketInfo{Name: bucket, Created: vi.Created}, nil
}

func (p *Pool) ListBuckets(ctx context.Context) ([]object.BucketInfo, error) {
	vis, err := p.sets[0].ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]object.BucketInfo, 0, len(vis))
	for _, v := range vis {
		out = append(out, object.BucketInfo{Name: v.Name, Created: v.Created})
	}
	return out, nil
}

func (p *Pool) DeleteBucket(ctx context.Context, bucket string, opts object.DeleteBucketOptions) error {
	p.bmu.Lock()
	delete(p.bucketsOK, bucket)
	p.bmu.Unlock()
	p.invalidateList(bucket)
	for _, set := range p.sets {
		if err := set.DeleteBucket(ctx, bucket, opts.Force); err != nil {
			if errors.Is(err, storage.ErrVolumeNotEmpty) {
				return object.ErrBucketNotEmpty
			}
			if errors.Is(err, storage.ErrVolumeNotFound) {
				return object.BucketNotFound{Bucket: bucket}
			}
			return err
		}
	}
	return nil
}

// --- objects ------------------------------------------------------

func (p *Pool) PutObject(ctx context.Context, bucket, key string, data *object.PutObjReader, opts object.ObjectOptions) (object.ObjectInfo, error) {
	defer p.invalidateList(bucket)
	if opts.Versioned || opts.VersionSuspended {
		return p.putObjectVersioned(ctx, bucket, key, data, opts)
	}
	if err := p.ensureBucket(ctx, bucket); err != nil {
		return object.ObjectInfo{}, err
	}
	if !validObjectName(key) {
		return object.ObjectInfo{}, object.ErrObjectNameInvalid
	}
	lk := p.NewNSLock(bucket, key)
	c, _ := lk.GetLock(ctx, 0)
	defer lk.Unlock(c)

	if opts.CheckPrecondFn != nil {
		if m, err := p.locate(ctx, bucket, key).statObject(ctx, bucket, key); err == nil {
			if opts.CheckPrecondFn(metaToInfo(bucket, key, m)) {
				return object.ObjectInfo{}, object.ErrPreconditionFailed
			}
		}
	}

	var sp *sseParams
	if p.kms != nil {
		if v := opts.UserDefined["x-amz-server-side-encryption"]; v == "AES256" || v == "aws:kms" {
			var serr error
			if sp, serr = p.newSSEParams(); serr != nil {
				return object.ObjectInfo{}, serr
			}
		}
	}
	meta, err := p.setFor(key).putObjectSSE(ctx, bucket, key, []partSource{
		{Number: 1, Size: data.Size(), Reader: data},
	}, toUserMeta(opts), sp, dedupEnabled)
	if err != nil {
		return object.ObjectInfo{}, mapErr(err)
	}
	if !opts.MTime.IsZero() {
		meta.ModTime = opts.MTime.UTC()
	}
	return metaToInfo(bucket, key, meta), nil
}

func (p *Pool) GetObjectInfo(ctx context.Context, bucket, key string, opts object.ObjectOptions) (object.ObjectInfo, error) {
	if err := p.ensureBucket(ctx, bucket); err != nil {
		return object.ObjectInfo{}, err
	}
	rlk := p.NewNSLock(bucket, key)
	rc, _ := rlk.GetRLock(ctx, 0)
	defer rlk.RUnlock(rc)

	if opts.Versioned || opts.VersionSuspended || opts.VersionID != "" {
		oi, err := p.statVersioned(ctx, bucket, key, opts.VersionID)
		if err == nil || opts.VersionID != "" || !errors.Is(err, object.ErrObjectNotFound) {
			return oi, err
		}
		// VersionID=="" and nothing in the version store: fall through in case
		// this is an object that predates versioning.
	}
	m, err := p.locate(ctx, bucket, key).statObject(ctx, bucket, key)
	if err != nil {
		return object.ObjectInfo{}, mapErr(err)
	}
	return metaToInfo(bucket, key, m), nil
}

func (p *Pool) GetObjectNInfo(ctx context.Context, bucket, key string, rs *object.HTTPRangeSpec, _ http.Header, opts object.ObjectOptions) (*object.GetObjectReader, error) {
	if err := p.ensureBucket(ctx, bucket); err != nil {
		return nil, err
	}
	if opts.Versioned || opts.VersionSuspended || opts.VersionID != "" {
		gr, err := p.getVersioned(ctx, bucket, key, rs, opts)
		if err == nil || opts.VersionID != "" || !errors.Is(err, object.ErrObjectNotFound) {
			return gr, err
		}
	}
	set := p.locate(ctx, bucket, key)
	m, err := set.statObject(ctx, bucket, key)
	if err != nil {
		return nil, mapErr(err)
	}
	oi := metaToInfo(bucket, key, m)
	if opts.CheckPrecondFn != nil && opts.CheckPrecondFn(oi) {
		return nil, object.ErrPreconditionFailed
	}

	// logical (plaintext) size — differs from stored size when encrypted or
	// compressed at rest
	logical := m.Size
	if m.SSE != "" || m.Compressed != "" {
		logical = m.PlainSize
	}
	var off, length int64 = 0, logical
	if rs != nil {
		o, l, rerr := resolveRange(rs, logical)
		if rerr != nil {
			return nil, rerr
		}
		off, length = o, l
		oi.Size = length
	}

	if m.Tier != "" { // bytes live on a remote cold backend
		return p.getTiered(ctx, m, oi, off, length)
	}

	if m.Compressed != "" {
		// zstd isn't range-seekable: read the whole compressed stream, then
		// decode and slice to the requested plaintext range.
		pr, pw := io.Pipe()
		go func() {
			err := set.getObjectMeta(ctx, bucket, key, m, 0, m.Size, pw)
			_ = pw.CloseWithError(err)
		}()
		dr, derr := zstdDecompressRange(pr, off, length)
		if derr != nil {
			_ = pr.CloseWithError(derr)
			return nil, derr
		}
		return &object.GetObjectReader{ObjInfo: oi, ReadCloser: dr}, nil
	}

	if m.SSE != "" {
		if p.kms == nil {
			return nil, object.ErrCorruptedData
		}
		cipherOff, cipherLen := cipherRange(off, length, m.Size)
		pr, pw := io.Pipe()
		go func() {
			err := set.getObjectMeta(ctx, bucket, key, m, cipherOff, cipherLen, pw)
			_ = pw.CloseWithError(err)
		}()
		dr, derr := p.decryptReader(m, pr, off, length)
		if derr != nil {
			_ = pr.CloseWithError(derr)
			return nil, derr
		}
		return &object.GetObjectReader{ObjInfo: oi, ReadCloser: readCloser{dr, pr}}, nil
	}

	pr, pw := io.Pipe()
	go func() {
		err := set.getObjectMeta(ctx, bucket, key, m, off, length, pw)
		_ = pw.CloseWithError(err)
	}()
	return &object.GetObjectReader{ObjInfo: oi, ReadCloser: pr}, nil
}

type readCloser struct {
	r io.Reader
	c io.Closer
}

func (rc readCloser) Read(p []byte) (int, error) { return rc.r.Read(p) }
func (rc readCloser) Close() error               { return rc.c.Close() }

func (p *Pool) DeleteObject(ctx context.Context, bucket, key string, opts object.ObjectOptions) (object.ObjectInfo, error) {
	defer p.invalidateList(bucket)
	if err := p.ensureBucket(ctx, bucket); err != nil {
		return object.ObjectInfo{}, err
	}
	if !validObjectName(key) {
		return object.ObjectInfo{}, object.ErrObjectNameInvalid
	}
	if opts.Versioned || opts.VersionSuspended || opts.VersionID != "" {
		return p.deleteVersioned(ctx, bucket, key, opts)
	}
	lk := p.NewNSLock(bucket, key)
	c, _ := lk.GetLock(ctx, 0)
	defer lk.Unlock(c)
	set := p.locate(ctx, bucket, key)
	var tier, tierKey string
	if m, merr := set.readMeta(ctx, bucket, key); merr == nil {
		tier, tierKey = m.Tier, m.TierKey
	}
	if err := set.deleteObject(ctx, bucket, key); err != nil {
		return object.ObjectInfo{}, mapErr(err)
	}
	if tier != "" {
		if cl := tierClient(tier); cl != nil {
			go func() { _ = cl.Delete(context.Background(), tierKey) }()
		}
	}
	return object.ObjectInfo{Bucket: bucket, Name: key}, nil
}

func (p *Pool) DeleteObjects(ctx context.Context, bucket string, objs []object.ObjectToDelete, opts object.ObjectOptions) ([]object.DeletedObject, []error) {
	defer p.invalidateList(bucket)
	deleted := make([]object.DeletedObject, len(objs))
	errs := make([]error, len(objs))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i, o := range objs {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			if _, err := p.DeleteObject(ctx, bucket, name, opts); err != nil {
				errs[i] = err
				return
			}
			deleted[i] = object.DeletedObject{ObjectName: name}
		}(i, o.ObjectName)
	}
	wg.Wait()
	return deleted, errs
}

func (p *Pool) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, _ object.ObjectInfo, srcOpts, dstOpts object.ObjectOptions) (object.ObjectInfo, error) {
	defer p.invalidateList(dstBucket)
	src, err := p.GetObjectNInfo(ctx, srcBucket, srcObject, nil, nil, object.ObjectOptions{VersionID: srcOpts.VersionID})
	if err != nil {
		return object.ObjectInfo{}, err
	}
	defer src.Close()

	ud := map[string]string{}
	for k, v := range src.ObjInfo.UserDefined {
		ud[k] = v
	}
	if dstOpts.UserDefined["_directive"] == "REPLACE" {
		ud = dstOpts.UserDefined
	}
	pr := object.NewPutObjReader(src, src.ObjInfo.Size, src.ObjInfo.Size)
	return p.PutObject(ctx, dstBucket, dstObject, pr, object.ObjectOptions{
		UserDefined: ud, UserTags: dstOpts.UserTags,
		Versioned: dstOpts.Versioned, VersionSuspended: dstOpts.VersionSuspended,
	})
}

// --- helpers -----------------------------------------------------

const bucketExistTTL = 30 * time.Second

// ensureBucket verifies the bucket exists. A positive result is cached for a
// short TTL so the common case (many ops against a live bucket) doesn't fan
// a StatVol out to every disk on every request. A local DeleteBucket evicts;
// a bucket deleted on another node is still trusted for up to the TTL, after
// which the op fails at the set layer anyway.
func (p *Pool) ensureBucket(ctx context.Context, bucket string) error {
	if !validBucketName(bucket) {
		return object.ErrBucketNameInvalid
	}
	p.bmu.Lock()
	fresh := time.Since(p.bucketsOK[bucket]) < bucketExistTTL
	p.bmu.Unlock()
	if fresh {
		return nil
	}
	if _, err := p.sets[0].StatBucket(ctx, bucket); err != nil {
		return object.BucketNotFound{Bucket: bucket}
	}
	p.bmu.Lock()
	p.bucketsOK[bucket] = time.Now()
	p.bmu.Unlock()
	return nil
}

func toUserMeta(opts object.ObjectOptions) userMeta {
	um := userMeta{tags: opts.UserTags, user: map[string]string{}, compress: opts.Compress}
	for k, v := range opts.UserDefined {
		switch k {
		case "content-type":
			um.contentType = v
		case "content-encoding":
			um.contentEnc = v
		case "_directive":
		default:
			um.user[k] = v
		}
	}
	if len(um.user) == 0 {
		um.user = nil
	}
	return um
}

func metaToInfo(bucket, key string, m *XLMeta) object.ObjectInfo {
	size := m.Size
	if m.SSE != "" || m.Compressed != "" {
		size = m.PlainSize
	}
	oi := object.ObjectInfo{
		Bucket: bucket, Name: key,
		Size: size, ModTime: m.ModTime, ETag: m.ETag,
		ContentType: m.ContentType, ContentEncoding: m.ContentEnc,
		UserTags: m.UserTags, StorageClass: "STANDARD", IsLatest: true,
		VersionID:   m.VersionID,
		UserDefined: map[string]string{},
	}
	for k, v := range m.UserMeta {
		oi.UserDefined[k] = v
	}
	if m.ContentType != "" {
		oi.UserDefined["content-type"] = m.ContentType
	}
	if m.SSE != "" {
		oi.UserDefined["x-amz-server-side-encryption"] = m.SSE
	}
	for _, pt := range m.Parts {
		oi.Parts = append(oi.Parts, object.ObjectPartInfo{
			Number: pt.Number, Size: pt.Size, ActualSize: pt.ActualSize, ETag: pt.ETag,
		})
	}
	return oi
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, storage.ErrFileNotFound):
		return object.ErrObjectNotFound
	case errors.Is(err, ErrReadQuorum):
		return object.ErrReadQuorum
	case errors.Is(err, ErrWriteQuorum):
		return object.ErrWriteQuorum
	case errors.Is(err, ErrBitrot), errors.Is(err, ErrCorrupt), errors.Is(err, ErrObjectMismatch):
		return object.ErrCorruptedData
	default:
		return err
	}
}

func resolveRange(rs *object.HTTPRangeSpec, size int64) (off, length int64, err error) {
	if rs.IsSuffixLength {
		n := -rs.Start
		if n <= 0 {
			return 0, 0, object.ErrInvalidRange
		}
		if n > size {
			n = size
		}
		return size - n, n, nil
	}
	if rs.Start < 0 || rs.Start >= size {
		return 0, 0, object.ErrInvalidRange
	}
	end := rs.End
	if end < 0 || end >= size {
		end = size - 1
	}
	if end < rs.Start {
		return 0, 0, object.ErrInvalidRange
	}
	return rs.Start, end - rs.Start + 1, nil
}
