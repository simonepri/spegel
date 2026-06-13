package estargz

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/opencontainers/go-digest"

	"github.com/spegel-org/spegel/pkg/oci"
)

var _ oci.BlobBackend = &Backend{}

// Backend serves blobs from the chunk cache of the stargz snapshotter. The snapshotter
// caches blobs as fixed size chunks named with the hash of the blob URL and the chunk
// range. When the snapshotter is configured to pull through the local Spegel mirror,
// the blob URL is deterministic and every chunk of a blob can be located, making the
// blob servable once the background fetch of the snapshotter has cached every chunk.
type Backend struct {
	// cachePath is the http cache directory of the stargz snapshotter.
	cachePath string
	// markerPath is the directory where verified blobs are recorded.
	markerPath string
	// mirrorScheme and mirrorHost mirror the resolver configuration of the snapshotter.
	mirrorScheme string
	mirrorHost   string
	chunkSize    int64
}

func NewBackend(cachePath, markerPath string, mirrorURL url.URL, chunkSize int64) (*Backend, error) {
	if chunkSize <= 0 {
		return nil, fmt.Errorf("chunk size has to be positive, got %d", chunkSize)
	}
	if mirrorURL.Scheme == "" || mirrorURL.Host == "" {
		return nil, fmt.Errorf("mirror url needs a scheme and a host, got %s", mirrorURL.String())
	}
	err := os.MkdirAll(markerPath, 0o755)
	if err != nil {
		return nil, err
	}
	b := &Backend{
		cachePath:    cachePath,
		markerPath:   markerPath,
		mirrorScheme: mirrorURL.Scheme,
		mirrorHost:   path.Join(mirrorURL.Host, mirrorURL.Path),
		chunkSize:    chunkSize,
	}
	return b, nil
}

// Complete returns true when every chunk of the blob is cached and the cached chunks
// have been verified to reproduce the blob digest. Verification runs once and is
// recorded in a marker file, while the presence of the chunks is checked every time
// so that cache garbage collection is observed.
func (b *Backend) Complete(ctx context.Context, ref oci.Reference, size int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	chunks := b.chunks(ref, size)
	for _, chunk := range chunks {
		_, err := os.Stat(chunk)
		if errors.Is(err, os.ErrNotExist) {
			err := os.Remove(b.markerFile(ref))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, err
			}
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	if b.hasMarker(ref) {
		return true, nil
	}
	err := b.verify(ctx, ref, chunks, size)
	if err != nil {
		return false, err
	}
	err = os.WriteFile(b.markerFile(ref), nil, 0o644)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Open returns a reader for the blob which reads from the cached chunks.
func (b *Backend) Open(ctx context.Context, ref oci.Reference, size int64) (io.ReadSeekCloser, error) {
	if !b.hasMarker(ref) {
		return nil, fmt.Errorf("blob %s has not been verified as complete", ref.Digest.String())
	}
	return newChunkReader(b.chunks(ref, size), b.chunkSize, size), nil
}

// verify reads every chunk of the blob and compares the digest of the concatenated
// content with the blob digest, guaranteeing that the chunk layout is correct and the
// reconstructed blob is identical to the original.
func (b *Backend) verify(ctx context.Context, ref oci.Reference, chunks []string, size int64) error {
	rc := newChunkReader(chunks, b.chunkSize, size)
	dgst, err := digest.FromReader(&contextReader{ctx: ctx, reader: rc})
	if err != nil {
		return err
	}
	if dgst != ref.Digest {
		return fmt.Errorf("cached chunks for blob %s reproduce digest %s", ref.Digest.String(), dgst.String())
	}
	return nil
}

// chunkKey returns the name of the cache file holding the given chunk range of the
// blob, matching the key scheme of the chunk cache of the stargz snapshotter.
func chunkKey(blobURL string, begin, end int64) string {
	return fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "%s-%d-%d", blobURL, begin, end)))
}

// chunks returns the cache file path of every chunk of the blob in order. The
// snapshotter creates a uniquely named cache directory every time it starts and
// leaves the previous ones behind, so every chunk is searched for in all cache
// directories. Chunks which are not found in any directory get a path in the cache
// root, which never exists.
func (b *Backend) chunks(ref oci.Reference, size int64) []string {
	dirs := []string{}
	entries, err := os.ReadDir(b.cachePath)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dirs = append(dirs, entry.Name())
		}
	}
	blobURL := b.blobURL(ref)
	chunks := []string{}
	for begin := int64(0); begin < size; begin += b.chunkSize {
		key := chunkKey(blobURL, begin, min(begin+b.chunkSize, size)-1)
		chunks = append(chunks, b.findChunk(dirs, key))
	}
	return chunks
}

// findChunk returns the path of the chunk in the first cache directory holding it,
// falling back to a path in the cache root which never exists.
func (b *Backend) findChunk(dirs []string, key string) string {
	for _, dir := range dirs {
		path := filepath.Join(b.cachePath, dir, key[:2], key)
		_, err := os.Stat(path)
		if err == nil {
			return path
		}
	}
	return filepath.Join(b.cachePath, key)
}

// blobURL returns the URL the snapshotter fetched the blob from, which identifies the
// blob and its chunks in the cache.
func (b *Backend) blobURL(ref oci.Reference) string {
	return fmt.Sprintf("%s://%s/v2/%s/blobs/%s", b.mirrorScheme, b.mirrorHost, ref.Repository, ref.Digest.String())
}

// markerFile is named after the blob URL instead of the digest, as the same blob can be
// cached under multiple repositories with separate chunks which are verified separately.
func (b *Backend) markerFile(ref oci.Reference) string {
	return filepath.Join(b.markerPath, fmt.Sprintf("%x", sha256.Sum256([]byte(b.blobURL(ref)))))
}

func (b *Backend) hasMarker(ref oci.Reference) bool {
	_, err := os.Stat(b.markerFile(ref))
	return err == nil
}

// chunkReader reads a blob from its cached chunks as a single continuous stream.
type chunkReader struct {
	*io.SectionReader
}

func newChunkReader(chunks []string, chunkSize, size int64) *chunkReader {
	ra := &chunkReaderAt{
		chunks:    chunks,
		chunkSize: chunkSize,
		size:      size,
	}
	return &chunkReader{io.NewSectionReader(ra, 0, size)}
}

func (r *chunkReader) Close() error {
	return nil
}

var _ io.Reader = &contextReader{}

// contextReader fails reads when the context is cancelled, bounding the duration of
// reads over large blobs.
type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

var _ io.ReaderAt = &chunkReaderAt{}

// chunkReaderAt reads ranges of a blob from its cached chunks.
type chunkReaderAt struct {
	chunks    []string
	chunkSize int64
	size      int64
}

func (r *chunkReaderAt) ReadAt(p []byte, off int64) (int, error) {
	read := 0
	for read < len(p) {
		if off >= r.size {
			return read, io.EOF
		}
		idx := off / r.chunkSize
		buf := p[read:min(int64(read)+min((idx+1)*r.chunkSize, r.size)-off, int64(len(p)))]
		file, err := os.Open(r.chunks[idx])
		if err != nil {
			return read, err
		}
		n, err := file.ReadAt(buf, off%r.chunkSize)
		file.Close()
		read += n
		off += int64(n)
		if err != nil && !errors.Is(err, io.EOF) {
			return read, err
		}
		if errors.Is(err, io.EOF) && n < len(buf) {
			return read, fmt.Errorf("chunk %s is shorter than expected", r.chunks[idx])
		}
	}
	return read, nil
}
