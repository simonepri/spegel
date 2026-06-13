package estargz

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-openapi/testify/v2/require"
	"github.com/opencontainers/go-digest"

	"github.com/spegel-org/spegel/pkg/oci"
)

// writeChunks writes blob content to a uniquely named directory in the cache with the
// same chunk layout and naming as the stargz snapshotter.
func writeChunks(t *testing.T, cachePath, cacheDir string, ref oci.Reference, content []byte, chunkSize int64) []string {
	t.Helper()

	blobURL := fmt.Sprintf("http://127.0.0.1:30020/v2/%s/blobs/%s", ref.Repository, ref.Digest.String())
	chunks := []string{}
	for begin := int64(0); begin < int64(len(content)); begin += chunkSize {
		end := min(begin+chunkSize, int64(len(content))) - 1
		key := fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "%s-%d-%d", blobURL, begin, end)))
		path := filepath.Join(cachePath, cacheDir, key[:2], key)
		err := os.MkdirAll(filepath.Dir(path), 0o755)
		require.NoError(t, err)
		err = os.WriteFile(path, content[begin:end+1], 0o644)
		require.NoError(t, err)
		chunks = append(chunks, path)
	}
	return chunks
}

func testBackend(t *testing.T, chunkSize int64) (*Backend, string) {
	t.Helper()

	cachePath := t.TempDir()
	mirrorURL, err := url.Parse("http://127.0.0.1:30020")
	require.NoError(t, err)
	backend, err := NewBackend(cachePath, t.TempDir(), *mirrorURL, chunkSize)
	require.NoError(t, err)
	return backend, cachePath
}

func testBlob(t *testing.T, size int64) (oci.Reference, []byte) {
	t.Helper()

	content := make([]byte, size)
	_, err := rand.Read(content)
	require.NoError(t, err)
	ref := oci.Reference{
		Registry:   "ghcr.io",
		Repository: "spegel-org/test",
		Digest:     digest.FromBytes(content),
	}
	return ref, content
}

func TestBackendComplete(t *testing.T) {
	t.Parallel()

	chunkSize := int64(100)
	backend, cachePath := testBackend(t, chunkSize)
	ref, content := testBlob(t, 1050)

	// Blob with no cached chunks is not complete.
	complete, err := backend.Complete(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	require.False(t, complete)

	// Blob with a missing chunk is not complete.
	chunks := writeChunks(t, cachePath, "1000000000", ref, content, chunkSize)
	err = os.Remove(chunks[3])
	require.NoError(t, err)
	complete, err = backend.Complete(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	require.False(t, complete)

	// Blob with every chunk cached is complete.
	writeChunks(t, cachePath, "1000000000", ref, content, chunkSize)
	complete, err = backend.Complete(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	require.True(t, complete)

	// Completeness is lost when the cache is garbage collected.
	err = os.Remove(chunks[5])
	require.NoError(t, err)
	complete, err = backend.Complete(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	require.False(t, complete)

	// Completeness is regained when the chunk is cached again.
	writeChunks(t, cachePath, "1000000000", ref, content, chunkSize)
	complete, err = backend.Complete(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	require.True(t, complete)
}

func TestBackendCompleteCorrupt(t *testing.T) {
	t.Parallel()

	chunkSize := int64(100)
	backend, cachePath := testBackend(t, chunkSize)
	ref, content := testBlob(t, 250)

	// Verification fails when a cached chunk holds wrong content.
	chunks := writeChunks(t, cachePath, "1000000000", ref, content, chunkSize)
	err := os.WriteFile(chunks[1], make([]byte, chunkSize), 0o644)
	require.NoError(t, err)
	_, err = backend.Complete(t.Context(), ref, int64(len(content)))
	require.Error(t, err)
}

func TestBackendCompleteAcrossCacheDirs(t *testing.T) {
	t.Parallel()

	chunkSize := int64(100)
	backend, cachePath := testBackend(t, chunkSize)
	ref, content := testBlob(t, 1050)

	// The snapshotter creates a new cache directory on every start, leaving chunks of a
	// blob spread over multiple directories when it restarts during a background fetch.
	chunks := writeChunks(t, cachePath, "1000000000", ref, content, chunkSize)
	for _, chunk := range chunks[:5] {
		err := os.Remove(chunk)
		require.NoError(t, err)
	}
	writeChunks(t, cachePath, "2000000000", ref, content[:5*chunkSize], chunkSize)
	complete, err := backend.Complete(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	require.True(t, complete)
}

func TestBackendOpen(t *testing.T) {
	t.Parallel()

	chunkSize := int64(100)
	backend, cachePath := testBackend(t, chunkSize)
	ref, content := testBlob(t, 1050)
	writeChunks(t, cachePath, "1000000000", ref, content, chunkSize)

	// Open requires the blob to have been verified as complete.
	_, err := backend.Open(t.Context(), ref, int64(len(content)))
	require.Error(t, err)
	complete, err := backend.Complete(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	require.True(t, complete)

	// The full read reproduces the blob.
	rc, err := backend.Open(t.Context(), ref, int64(len(content)))
	require.NoError(t, err)
	b, err := io.ReadAll(rc)
	require.NoError(t, err)
	require.Equal(t, content, b)
	err = rc.Close()
	require.NoError(t, err)

	// Reads from an offset reproduce the blob range, including ranges crossing
	// chunk boundaries and ranges in the last partial chunk.
	for _, offset := range []int64{0, 1, 99, 100, 150, 999, 1000, 1049} {
		rc, err := backend.Open(t.Context(), ref, int64(len(content)))
		require.NoError(t, err)
		n, err := rc.Seek(offset, io.SeekStart)
		require.NoError(t, err)
		require.EqualT(t, offset, n)
		b, err := io.ReadAll(rc)
		require.NoError(t, err)
		require.Equal(t, content[offset:], b)
		err = rc.Close()
		require.NoError(t, err)
	}
}
