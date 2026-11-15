package publisher

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Retain the canonical segments and current STIX artifacts between full passes.
// Leave room on the dedicated 512 MiB volume for a maximum-size feed file.
// Writes also evict before creating their temporary file, bounding peak usage.
const defaultBlobCacheBytes int64 = 384 << 20

// WithBlobCache enables a bounded disk cache of immutable raw Git blob bytes.
// dir must be dedicated to this cache. Empty disables it. Metadata lookups and
// publication read tracking still run on every read; no decoded data is retained.
func WithBlobCache(dir string) PublisherOption {
	return func(p *Publisher) {
		p.blobCache = nil
		if dir != "" {
			p.blobCache = &blobDiskCache{dir: dir, maxBytes: defaultBlobCacheBytes}
		}
	}
}

type blobDiskCache struct {
	dir      string
	maxBytes int64
}

func validBlobSHA(sha string) bool {
	if len(sha) != 40 {
		return false
	}
	for _, ch := range sha {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func validateBlobBytes(sha string, size int64, data []byte) error {
	if !validBlobSHA(sha) || gitBlobSHA(data) != sha {
		return fmt.Errorf("git blob content does not match SHA %q", sha)
	}
	if size < 0 || size > maxFeedFileBytes || int64(len(data)) != size {
		return fmt.Errorf("git blob %s has %d bytes, expected %d within the feed limit", sha, len(data), size)
	}
	return nil
}

// The file lock covers independent publishers/processes sharing a directory,
// including the eviction reservation and temporary write. Cache failures are
// misses; the remote store remains authoritative.
func (c *blobDiskCache) lock() (*os.File, error) {
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(c.dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func unlockBlobCache(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

func (c *blobDiskCache) get(sha string, size int64) []byte {
	if !validBlobSHA(sha) || size < 0 || size > min(c.maxBytes, maxFeedFileBytes) {
		return nil
	}
	lock, err := c.lock()
	if err != nil {
		return nil
	}
	defer unlockBlobCache(lock)
	path := filepath.Join(c.dir, sha+".blob")
	info, err := os.Lstat(path)
	if err != nil {
		return nil
	}
	if !info.Mode().IsRegular() || info.Size() != size {
		_ = os.Remove(path)
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	data, err := readFeedFile(f, size, size)
	closeErr := f.Close()
	if err != nil || closeErr != nil || validateBlobBytes(sha, size, data) != nil {
		_ = os.Remove(path)
		return nil
	}
	now := time.Now()
	_ = os.Chtimes(path, now, now)
	return data
}

func (c *blobDiskCache) put(sha string, data []byte) error {
	if err := validateBlobBytes(sha, int64(len(data)), data); err != nil {
		return err
	}
	size := int64(len(data))
	if size > c.maxBytes {
		return nil
	}
	lock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlockBlobCache(lock)
	target := filepath.Join(c.dir, sha+".blob")
	// Remove the old copy before reserving space for an atomic replacement.
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	type cachedFile struct {
		name string
		info os.FileInfo
	}
	var files []cachedFile
	var total int64
	for _, entry := range entries {
		// No writer can be active under the lock; these are crash leftovers.
		if strings.HasPrefix(entry.Name(), ".tmp-") {
			if err := os.Remove(filepath.Join(c.dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".blob") || !validBlobSHA(strings.TrimSuffix(entry.Name(), ".blob")) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		files = append(files, cachedFile{entry.Name(), info})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].info.ModTime().Equal(files[j].info.ModTime()) {
			return files[i].name < files[j].name
		}
		return files[i].info.ModTime().Before(files[j].info.ModTime())
	})
	for _, file := range files {
		if total+size <= c.maxBytes {
			break
		}
		if err := os.Remove(filepath.Join(c.dir, file.name)); err != nil {
			return err
		}
		total -= file.info.Size()
	}
	tmp, err := os.CreateTemp(c.dir, ".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), target)
}

func (p *Publisher) cacheDownloadedBlob(sha string, size int64, data []byte) error {
	if p.blobCache == nil {
		return nil
	}
	if err := validateBlobBytes(sha, size, data); err != nil {
		return err
	}
	if err := p.blobCache.put(sha, data); err != nil {
		p.logger.Warn("Git blob disk cache write failed", "error", err)
	}
	return nil
}
