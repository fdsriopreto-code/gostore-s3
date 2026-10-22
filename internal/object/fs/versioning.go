package fs

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lojadopocket/gostore/internal/object"
)

// Versioning is implemented as a per-key version log under
// <root>/.gostore.sys/objver/<bucket>/<key>/ :
//
//	index.json     ordered []verEntry (append order; newest last)
//	<versionId>    the data file for a non-delete-marker version
//
// A bucket is "versioned" per-request: the API layer passes opts.Versioned
// (state Enabled) or opts.VersionSuspended (state Suspended). When neither is
// set the plain unversioned code path in object.go / list.go is used.

const nullVersionID = "null"

type verEntry struct {
	ID           string            `json:"id"`
	DeleteMarker bool              `json:"dm,omitempty"`
	Size         int64             `json:"size"`
	ETag         string            `json:"etag,omitempty"`
	ModTime      time.Time         `json:"modTime"`
	ContentType  string            `json:"contentType,omitempty"`
	ContentEnc   string            `json:"contentEncoding,omitempty"`
	UserMeta     map[string]string `json:"userMeta,omitempty"`
	UserTags     string            `json:"userTags,omitempty"`
	Parts        []objMetaPart     `json:"parts,omitempty"`

	// Object Lock (WORM), per version.
	LockMode    string    `json:"lockMode,omitempty"` // GOVERNANCE | COMPLIANCE
	RetainUntil time.Time `json:"retainUntil,omitempty"`
	LegalHold   bool      `json:"legalHold,omitempty"`
}

// lockBlocks reports whether this version may not be deleted/overwritten now.
func (e verEntry) lockBlocks(bypassGovernance bool) bool {
	if e.LegalHold {
		return true
	}
	if e.RetainUntil.IsZero() || !time.Now().Before(e.RetainUntil) {
		return false
	}
	switch e.LockMode {
	case "COMPLIANCE":
		return true
	case "GOVERNANCE":
		return !bypassGovernance
	}
	return false
}

func (f *FS) verDir(bucket, obj string) string {
	return filepath.Join(f.root, sysDir, "objver", bucket, filepath.FromSlash(obj))
}
func (f *FS) verIndexPath(bucket, obj string) string {
	return filepath.Join(f.verDir(bucket, obj), "index.json")
}
func (f *FS) verDataPath(bucket, obj, id string) string {
	return filepath.Join(f.verDir(bucket, obj), id)
}

// newVersionID returns a lexically-sortable, time-ordered id (24 hex chars:
// 16 for big-endian unix-nanos, 8 random).
func newVersionID() string {
	var b [12]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixNano()))
	_, _ = rand.Read(b[8:])
	return hex.EncodeToString(b[:])
}

func (f *FS) readVerIndex(bucket, obj string) ([]verEntry, error) {
	b, err := os.ReadFile(f.verIndexPath(bucket, obj))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var idx []verEntry
	if err := json.Unmarshal(b, &idx); err != nil {
		return nil, err
	}
	return idx, nil
}

func (f *FS) writeVerIndex(bucket, obj string, idx []verEntry) error {
	b, _ := json.Marshal(idx)
	return writeFileAtomic(f.verIndexPath(bucket, obj), b, 0o644)
}

// migrateIfNeeded seeds the version log with the pre-existing plain object as
// the "null" version, the first time a versioned op touches that key.
func (f *FS) migrateIfNeeded(bucket, obj string, idx []verEntry) ([]verEntry, error) {
	if idx != nil {
		return idx, nil
	}
	st, err := os.Stat(f.objDataPath(bucket, obj))
	if err != nil || st.IsDir() {
		return idx, nil // nothing to migrate
	}
	m, merr := readMetaFile(f.objMetaPath(bucket, obj))
	if merr != nil {
		md5hex, herr := md5File(f.objDataPath(bucket, obj))
		if herr != nil {
			return idx, herr
		}
		m = objMeta{Size: st.Size(), ModTime: st.ModTime().UTC(), ETag: md5hex}
	}
	if err := os.MkdirAll(f.verDir(bucket, obj), 0o755); err != nil {
		return idx, err
	}
	// Move the plain data file into the version store as "null".
	if err := os.Rename(f.objDataPath(bucket, obj), f.verDataPath(bucket, obj, nullVersionID)); err != nil {
		return idx, err
	}
	_ = os.Remove(f.objMetaPath(bucket, obj))
	e := verEntry{
		ID: nullVersionID, Size: m.Size, ETag: m.ETag, ModTime: m.ModTime,
		ContentType: m.ContentType, ContentEnc: m.ContentEnc,
		UserMeta: m.UserMeta, UserTags: m.UserTags, Parts: m.Parts,
	}
	return []verEntry{e}, nil
}

// putVersion stores a new version (Enabled) or overwrites the null version
// (Suspended).
func (f *FS) putVersion(_ context.Context, bucket, obj string, data *object.PutObjReader, opts object.ObjectOptions) (object.ObjectInfo, error) {
	if err := f.ensureBucket(bucket); err != nil {
		return object.ObjectInfo{}, err
	}
	if !validObjectName(obj) {
		return object.ObjectInfo{}, object.ErrObjectNameInvalid
	}
	lk := f.NewNSLock(bucket, obj)
	c, _ := lk.GetLock(context.Background(), 0)
	defer lk.Unlock(c)

	idx, err := f.readVerIndex(bucket, obj)
	if err != nil {
		return object.ObjectInfo{}, err
	}
	if idx, err = f.migrateIfNeeded(bucket, obj, idx); err != nil {
		return object.ObjectInfo{}, err
	}

	id := newVersionID()
	if opts.VersionSuspended {
		id = nullVersionID
	}
	if err := os.MkdirAll(f.verDir(bucket, obj), 0o755); err != nil {
		return object.ObjectInfo{}, err
	}
	tmp, n, md5hex, err := f.copyToTmpAndHash(data, data.Size())
	if err != nil {
		return object.ObjectInfo{}, err
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, f.verDataPath(bucket, obj, id)); err != nil {
		return object.ObjectInfo{}, err
	}

	now := time.Now().UTC()
	if !opts.MTime.IsZero() {
		now = opts.MTime.UTC()
	}
	// Suspended overwrite of a locked "null" version is refused.
	if opts.VersionSuspended {
		for _, ex := range idx {
			if ex.ID == nullVersionID && ex.lockBlocks(opts.BypassGovernance) {
				return object.ObjectInfo{}, object.ErrObjectLocked
			}
		}
	}
	e := verEntry{
		ID: id, Size: n, ETag: md5hex, ModTime: now,
		ContentType: opts.UserDefined["content-type"],
		ContentEnc:  opts.UserDefined["content-encoding"],
		UserMeta:    stripReserved(opts.UserDefined),
		UserTags:    opts.UserTags,
		LockMode:    opts.LockMode,
		RetainUntil: opts.LockRetainUntil,
		LegalHold:   opts.LockLegalHold == "ON",
	}
	idx = replaceOrAppend(idx, e, opts.VersionSuspended)
	if err := f.writeVerIndex(bucket, obj, idx); err != nil {
		return object.ObjectInfo{}, err
	}
	return entryToInfo(bucket, obj, e, true), nil
}

// replaceOrAppend: Suspended replaces a trailing/any "null" entry; Enabled
// always appends.
func replaceOrAppend(idx []verEntry, e verEntry, suspended bool) []verEntry {
	if suspended {
		for i := range idx {
			if idx[i].ID == nullVersionID {
				// drop old null (data file overwritten already since same path)
				idx = append(idx[:i], idx[i+1:]...)
				break
			}
		}
	}
	return append(idx, e)
}

// deleteVersion adds a delete marker (versionID == "") or permanently removes
// a specific version.
func (f *FS) deleteVersion(_ context.Context, bucket, obj, versionID string, suspended, bypassGovernance bool) (object.ObjectInfo, error) {
	if !validObjectName(obj) {
		return object.ObjectInfo{}, object.ErrObjectNameInvalid
	}
	lk := f.NewNSLock(bucket, obj)
	c, _ := lk.GetLock(context.Background(), 0)
	defer lk.Unlock(c)

	idx, err := f.readVerIndex(bucket, obj)
	if err != nil {
		return object.ObjectInfo{}, err
	}
	if idx, err = f.migrateIfNeeded(bucket, obj, idx); err != nil {
		return object.ObjectInfo{}, err
	}

	if versionID == "" {
		id := newVersionID()
		if suspended {
			id = nullVersionID
			// remove an existing null so the marker replaces it
			for i := range idx {
				if idx[i].ID == nullVersionID {
					if !idx[i].DeleteMarker {
						_ = os.Remove(f.verDataPath(bucket, obj, nullVersionID))
					}
					idx = append(idx[:i], idx[i+1:]...)
					break
				}
			}
		}
		e := verEntry{ID: id, DeleteMarker: true, ModTime: time.Now().UTC()}
		idx = append(idx, e)
		if err := f.writeVerIndex(bucket, obj, idx); err != nil {
			return object.ObjectInfo{}, err
		}
		return object.ObjectInfo{Bucket: bucket, Name: obj, VersionID: id, DeleteMarker: true}, nil
	}

	// permanent delete of one version
	for i := range idx {
		if idx[i].ID == versionID {
			if idx[i].lockBlocks(bypassGovernance) {
				return object.ObjectInfo{}, object.ErrObjectLocked
			}
			if !idx[i].DeleteMarker {
				_ = os.Remove(f.verDataPath(bucket, obj, versionID))
			}
			idx = append(idx[:i], idx[i+1:]...)
			if len(idx) == 0 {
				_ = os.RemoveAll(f.verDir(bucket, obj))
				f.pruneEmptyDirs(filepath.Dir(f.verDir(bucket, obj)),
					filepath.Join(f.root, sysDir, "objver", bucket))
			} else if err := f.writeVerIndex(bucket, obj, idx); err != nil {
				return object.ObjectInfo{}, err
			}
			return object.ObjectInfo{Bucket: bucket, Name: obj, VersionID: versionID}, nil
		}
	}
	return object.ObjectInfo{}, object.ObjectNotFound{Bucket: bucket, Object: obj}
}

// latest returns the newest entry, or the one matching versionID.
func latestOrByID(idx []verEntry, versionID string) (verEntry, bool) {
	if versionID != "" {
		for _, e := range idx {
			if e.ID == versionID {
				return e, true
			}
		}
		return verEntry{}, false
	}
	if len(idx) == 0 {
		return verEntry{}, false
	}
	return idx[len(idx)-1], true
}

func (f *FS) getVersionInfo(bucket, obj, versionID string) (object.ObjectInfo, verEntry, error) {
	idx, err := f.readVerIndex(bucket, obj)
	if err != nil {
		return object.ObjectInfo{}, verEntry{}, err
	}
	if len(idx) == 0 {
		// maybe an un-migrated plain object
		if oi, perr := f.getInfoUnlocked(bucket, obj); perr == nil && versionID == "" {
			return oi, verEntry{}, nil
		}
		return object.ObjectInfo{}, verEntry{}, object.ObjectNotFound{Bucket: bucket, Object: obj}
	}
	e, ok := latestOrByID(idx, versionID)
	if !ok {
		return object.ObjectInfo{}, verEntry{}, object.ObjectNotFound{Bucket: bucket, Object: obj}
	}
	if e.DeleteMarker {
		return object.ObjectInfo{}, e, object.ObjectNotFound{Bucket: bucket, Object: obj}
	}
	return entryToInfo(bucket, obj, e, versionID == "" || e.ID == idx[len(idx)-1].ID), e, nil
}

func entryToInfo(bucket, obj string, e verEntry, isLatest bool) object.ObjectInfo {
	oi := object.ObjectInfo{
		Bucket: bucket, Name: obj, Size: e.Size, ETag: e.ETag, ModTime: e.ModTime,
		ContentType: e.ContentType, ContentEncoding: e.ContentEnc,
		UserTags: e.UserTags, StorageClass: "STANDARD",
		VersionID: e.ID, IsLatest: isLatest, DeleteMarker: e.DeleteMarker,
		UserDefined: map[string]string{},
	}
	for k, v := range e.UserMeta {
		oi.UserDefined[k] = v
	}
	if e.ContentType != "" {
		oi.UserDefined["content-type"] = e.ContentType
	}
	for _, p := range e.Parts {
		oi.Parts = append(oi.Parts, object.ObjectPartInfo{Number: p.Number, Size: p.Size, ActualSize: p.ActualSize, ETag: p.ETag})
	}
	return oi
}

// walkVerKeys returns every key that has a version log.
func (f *FS) walkVerKeys(bucket string) ([]string, error) {
	root := filepath.Join(f.root, sysDir, "objver", bucket)
	var keys []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return filepath.SkipDir
			}
			return err
		}
		if d.Name() == "index.json" {
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			keys = append(keys, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	sort.Strings(keys)
	return keys, nil
}

// listVersioned emits all versions (ListObjectVersions) or just current
// non-delete-marker heads (currentOnly, for ListObjectsV2 on a versioned
// bucket).
func (f *FS) listVersioned(bucket, prefix, delimiter string, maxKeys int, currentOnly bool) (object.ListObjectVersionsInfo, error) {
	if err := f.ensureBucket(bucket); err != nil {
		return object.ListObjectVersionsInfo{}, err
	}
	if maxKeys <= 0 || maxKeys > 1000 {
		maxKeys = 1000
	}
	// union: keys with a version log + plain (un-migrated) keys
	verKeys, err := f.walkVerKeys(bucket)
	if err != nil {
		return object.ListObjectVersionsInfo{}, err
	}
	plainKeys, err := f.walkKeys(bucket)
	if err != nil {
		return object.ListObjectVersionsInfo{}, err
	}
	seen := map[string]bool{}
	var keys []string
	for _, k := range append(verKeys, plainKeys...) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var out object.ListObjectVersionsInfo
	prefixes := map[string]bool{}
	count := 0
	for _, k := range keys {
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		if delimiter != "" {
			rest := k[len(prefix):]
			if i := strings.Index(rest, delimiter); i >= 0 {
				cp := prefix + rest[:i+len(delimiter)]
				if !prefixes[cp] {
					prefixes[cp] = true
					out.Prefixes = append(out.Prefixes, cp)
				}
				continue
			}
		}
		idx, _ := f.readVerIndex(bucket, k)
		if len(idx) == 0 {
			if oi, perr := f.getInfoUnlocked(bucket, k); perr == nil {
				oi.VersionID = nullVersionID
				oi.IsLatest = true
				out.Objects = append(out.Objects, oi)
				count++
			}
			continue
		}
		if currentOnly {
			e := idx[len(idx)-1]
			if e.DeleteMarker {
				continue
			}
			out.Objects = append(out.Objects, entryToInfo(bucket, k, e, true))
			count++
			if count >= maxKeys {
				out.IsTruncated = true
				break
			}
			continue
		}
		for i := len(idx) - 1; i >= 0; i-- {
			out.Objects = append(out.Objects, entryToInfo(bucket, k, idx[i], i == len(idx)-1))
			count++
			if count >= maxKeys {
				out.IsTruncated = true
				break
			}
		}
		if out.IsTruncated {
			break
		}
	}
	sort.Strings(out.Prefixes)
	return out, nil
}

// openVersionData opens a version's data file (range handled by the caller).
func (f *FS) openVersionData(bucket, obj, versionID string, e verEntry) (*os.File, error) {
	id := versionID
	if id == "" {
		id = e.ID
	}
	if id == "" {
		return os.Open(f.objDataPath(bucket, obj)) // un-migrated plain object
	}
	return os.Open(f.verDataPath(bucket, obj, id))
}
