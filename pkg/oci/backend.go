package oci

import (
	"context"
	"io"
)

// BlobBackend serves blobs which are not present in the containerd content store.
// Remote snapshotters store lazily pulled layers in their own caches, from where
// they can be served once every byte of the blob is present.
type BlobBackend interface {
	// Complete returns true when every byte of the blob is present and verified.
	Complete(ctx context.Context, ref Reference, size int64) (bool, error)

	// Open returns a reader for a complete blob.
	Open(ctx context.Context, ref Reference, size int64) (io.ReadSeekCloser, error)
}
