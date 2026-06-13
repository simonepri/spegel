package oci

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	eventtypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"
	"github.com/go-logr/logr"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pelletier/go-toml/v2"
	tomlu "github.com/pelletier/go-toml/v2/unstable"

	"github.com/spegel-org/spegel/internal/option"
	"github.com/spegel-org/spegel/internal/resilient"
	"github.com/spegel-org/spegel/pkg/httpx"
)

const (
	backupDir       = "_backup"
	listImageFilter = `name~="^.+/"`
)

type ContainerdConfig struct {
	ContentPath         string
	BlobBackend         BlobBackend
	BackendPollInterval time.Duration
}

type ContainerdOption = option.Option[ContainerdConfig]

func WithContentPath(path string) ContainerdOption {
	return func(c *ContainerdConfig) error {
		c.ContentPath = path
		return nil
	}
}

// WithBlobBackend sets a backend which serves blobs that are missing from the content
// store, like layers of lazily pulled images. Blobs which the backend reports as
// complete are advertised and served as if they were present in the content store.
func WithBlobBackend(backend BlobBackend, pollInterval time.Duration) ContainerdOption {
	return func(c *ContainerdConfig) error {
		c.BlobBackend = backend
		c.BackendPollInterval = pollInterval
		return nil
	}
}

var _ Store = &Containerd{}

// lazyBlob is a blob which is missing from the content store and may be served by the
// blob backend. The descriptor comes from the manifest referencing the blob.
type lazyBlob struct {
	ref      Reference
	desc     ocispec.Descriptor
	complete bool
}

type Containerd struct {
	client       *client.Client
	mediaTypeIdx *lru.Cache[digest.Digest, string]
	contentPath  string

	backend             BlobBackend
	backendPollInterval time.Duration
	lazyMu              sync.RWMutex
	lazyBlobs           map[digest.Digest]*lazyBlob
}

func NewContainerd(ctx context.Context, sock, namespace string, opts ...ContainerdOption) (*Containerd, error) {
	cfg := ContainerdConfig{
		BackendPollInterval: 30 * time.Second,
	}
	err := option.Apply(&cfg, opts...)
	if err != nil {
		return nil, err
	}

	client, err := client.New(sock, client.WithDefaultNamespace(namespace))
	if err != nil {
		return nil, err
	}
	mediaTypeIdx, err := lru.New[digest.Digest, string](100)
	if err != nil {
		return nil, err
	}
	c := &Containerd{
		client:              client,
		mediaTypeIdx:        mediaTypeIdx,
		contentPath:         cfg.ContentPath,
		backend:             cfg.BlobBackend,
		backendPollInterval: cfg.BackendPollInterval,
		lazyBlobs:           map[digest.Digest]*lazyBlob{},
	}
	return c, nil
}

func (c *Containerd) Close() error {
	err := c.client.Close()
	if err != nil {
		return err
	}
	return nil
}

func (c *Containerd) Name() string {
	return "containerd"
}

func (c *Containerd) ListImages(ctx context.Context) ([]Image, error) {
	cImgs, err := c.client.ImageService().List(ctx, listImageFilter)
	if err != nil {
		return nil, err
	}
	tagDgsts := map[digest.Digest]string{}
	imgs := []Image{}
	for _, cImg := range cImgs {
		img, err := ParseImage(cImg.Name, WithDigest(cImg.Target.Digest))
		if err != nil {
			return nil, err
		}
		if img.Tag != "" {
			tagDgsts[img.Digest] = img.Tag
		}
		imgs = append(imgs, img)
	}
	// Remove duplicate digest images that already have tags.
	imgs = slices.DeleteFunc(imgs, func(img Image) bool {
		if img.Tag != "" {
			return false
		}
		if _, ok := tagDgsts[img.Digest]; ok {
			return true
		}
		return false
	})
	return imgs, nil
}

func (c *Containerd) Resolve(ctx context.Context, ref string) (digest.Digest, error) {
	cImg, err := c.client.ImageService().Get(ctx, ref)
	if err != nil {
		return "", err
	}
	return cImg.Target.Digest, nil
}

func (c *Containerd) Descriptor(ctx context.Context, dgst digest.Digest) (ocispec.Descriptor, error) {
	info, err := c.client.ContentStore().Info(ctx, dgst)
	if errors.Is(err, errdefs.ErrNotFound) {
		if lb, ok := c.completeLazyBlob(dgst); ok {
			return lb.desc, nil
		}
		return ocispec.Descriptor{}, errors.Join(ErrNotFound, err)
	}
	if err != nil {
		return ocispec.Descriptor{}, err
	}

	mt, ok := c.mediaTypeIdx.Get(dgst)
	if !ok {
		mt, err = func() (string, error) {
			if info.Size > ManifestMaxSize {
				return httpx.ContentTypeBinary, nil
			}
			rc, err := c.Open(ctx, dgst)
			if err != nil {
				return "", err
			}
			defer rc.Close()
			mt, err := FingerprintMediaType(rc)
			if err != nil {
				return "", err
			}
			return mt, nil
		}()
		if err != nil {
			return ocispec.Descriptor{}, err
		}
		c.mediaTypeIdx.Add(dgst, mt)
	}

	desc := ocispec.Descriptor{
		Size:      info.Size,
		Digest:    dgst,
		MediaType: mt,
	}
	return desc, nil
}

func (c *Containerd) Open(ctx context.Context, dgst digest.Digest) (io.ReadSeekCloser, error) {
	if c.contentPath != "" {
		path := filepath.Join(c.contentPath, "blobs", dgst.Algorithm().String(), dgst.Encoded())
		file, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			if lb, ok := c.completeLazyBlob(dgst); ok {
				return c.backend.Open(ctx, lb.ref, lb.desc.Size)
			}
			return nil, errors.Join(ErrNotFound, err)
		}
		if err != nil {
			return nil, err
		}
		return file, nil
	}
	ra, err := c.client.ContentStore().ReaderAt(ctx, ocispec.Descriptor{Digest: dgst})
	if errors.Is(err, errdefs.ErrNotFound) {
		if lb, ok := c.completeLazyBlob(dgst); ok {
			return c.backend.Open(ctx, lb.ref, lb.desc.Size)
		}
		return nil, errors.Join(ErrNotFound, err)
	}
	if err != nil {
		return nil, err
	}
	return struct {
		io.ReadSeeker
		io.Closer
	}{
		ReadSeeker: io.NewSectionReader(ra, 0, ra.Size()),
		Closer:     ra,
	}, nil
}

func (c *Containerd) Subscribe(ctx context.Context) (map[Image][]digest.Digest, <-chan OCIEvent, error) {
	log := logr.FromContextOrDiscard(ctx)

	eventCh := make(chan OCIEvent)
	subCtx, subCancel := context.WithCancel(ctx)
	eventFilters := []string{`topic~="/images/create|/images/delete",event.name~="^.+/"`, `topic~="/content/create"`}
	envelopeCh, cErrCh := c.client.EventService().Subscribe(subCtx, eventFilters...)

	// Populate the content index.
	initial := map[Image][]digest.Digest{}
	contentIdx := map[digest.Digest][]Reference{}
	cImgs, err := c.client.ImageService().List(ctx, listImageFilter)
	if err != nil {
		subCancel()
		return nil, nil, err
	}
	for _, cImg := range cImgs {
		img, err := ParseImage(cImg.Name, WithDigest(cImg.Target.Digest))
		if err != nil {
			log.Error(err, "skipping image that cannot be parsed", "image", img.String())
			continue
		}
		refs := []Reference{}
		descs := map[digest.Digest]ocispec.Descriptor{}
		handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			children, err := images.ChildrenHandler(c.client.ContentStore()).Handle(ctx, desc)
			if errors.Is(err, errdefs.ErrNotFound) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			ref := Reference{
				Registry:   img.Registry,
				Repository: img.Repository,
				Digest:     desc.Digest,
			}
			refs = append(refs, ref)
			descs[desc.Digest] = desc
			return children, nil
		})
		err = images.Walk(ctx, handler, cImg.Target)
		if err != nil {
			log.Error(err, "skipping image that cannot be walked", "image", img.String())
			continue
		}
		contentIdx[cImg.Target.Digest] = refs

		// The walk does not read leaf content like layers, so their existence has to be
		// checked before advertising. Lazily pulled images have layers which are missing
		// from the content store and cannot be served.
		dgsts, err := c.existingDigests(ctx, refs)
		if err != nil {
			log.Error(err, "skipping image that cannot be checked for existing content", "image", img.String())
			continue
		}
		c.registerLazyBlobs(refs, descs, dgsts)
		initial[img] = dgsts
	}

	backendCh := make(chan OCIEvent)
	if c.backend != nil {
		go c.pollBackend(logr.NewContext(subCtx, log), backendCh)
	}
	go func() {
		defer close(eventCh)
		for {
			select {
			case <-subCtx.Done():
				return
			case event := <-backendCh:
				eventCh <- event
			case envelope := <-envelopeCh:
				events, err := c.handleEvent(subCtx, *envelope, contentIdx)
				if err != nil {
					log.Error(err, "error when handling containerd event")
					continue
				}
				for _, event := range events {
					eventCh <- event
				}
			}
		}
	}()
	go func() {
		// Required so that the event channel closes in case containerd is restarted.
		defer subCancel()
		for err := range cErrCh {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Error(err, "received containerd event error")
		}
	}()
	return initial, eventCh, nil
}

// existingDigests returns the digests of the references which exist in the content store.
func (c *Containerd) existingDigests(ctx context.Context, refs []Reference) ([]digest.Digest, error) {
	dgsts := []digest.Digest{}
	for _, ref := range refs {
		_, err := c.client.ContentStore().Info(ctx, ref.Digest)
		if errors.Is(err, errdefs.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		dgsts = append(dgsts, ref.Digest)
	}
	return dgsts, nil
}

// registerLazyBlobs indexes references which are not part of the existing digests so
// that the blob backend can serve them once they are complete. Completeness is
// checked by the backend poller, which advertises the blobs that are complete.
func (c *Containerd) registerLazyBlobs(refs []Reference, descs map[digest.Digest]ocispec.Descriptor, existing []digest.Digest) {
	if c.backend == nil {
		return
	}
	c.lazyMu.Lock()
	defer c.lazyMu.Unlock()
	for _, ref := range refs {
		if slices.Contains(existing, ref.Digest) {
			continue
		}
		desc, ok := descs[ref.Digest]
		if !ok {
			continue
		}
		if _, ok := c.lazyBlobs[ref.Digest]; !ok {
			c.lazyBlobs[ref.Digest] = &lazyBlob{ref: ref, desc: desc}
		}
	}
}

// completeLazyBlob returns the lazy blob for the digest if it is complete.
func (c *Containerd) completeLazyBlob(dgst digest.Digest) (*lazyBlob, bool) {
	if c.backend == nil {
		return nil, false
	}
	c.lazyMu.RLock()
	defer c.lazyMu.RUnlock()
	lb, ok := c.lazyBlobs[dgst]
	return lb, ok && lb.complete
}

// pollBackend periodically checks the completeness of lazy blobs, advertising blobs
// which have become complete and withdrawing blobs which are no longer complete, for
// example when the backend cache is garbage collected.
func (c *Containerd) pollBackend(ctx context.Context, eventCh chan<- OCIEvent) {
	log := logr.FromContextOrDiscard(ctx)
	ticker := time.NewTicker(c.backendPollInterval)
	defer ticker.Stop()
	for {
		c.lazyMu.RLock()
		lbs := make([]*lazyBlob, 0, len(c.lazyBlobs))
		for _, lb := range c.lazyBlobs {
			lbs = append(lbs, lb)
		}
		c.lazyMu.RUnlock()
		for _, lb := range lbs {
			complete, err := c.backend.Complete(ctx, lb.ref, lb.desc.Size)
			if err != nil {
				log.Error(err, "could not check blob completeness", "digest", lb.ref.Digest.String())
				continue
			}
			c.lazyMu.Lock()
			changed := lb.complete != complete
			lb.complete = complete
			c.lazyMu.Unlock()
			if !changed {
				continue
			}
			eventType := CreateEvent
			if !complete {
				eventType = DeleteEvent
			}
			select {
			case eventCh <- OCIEvent{Type: eventType, Reference: lb.ref}:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Containerd) handleEvent(ctx context.Context, envelope events.Envelope, contentIdx map[digest.Digest][]Reference) ([]OCIEvent, error) {
	if envelope.Event == nil {
		return nil, errors.New("envelope event cannot be nil")
	}
	evt, err := typeurl.UnmarshalAny(envelope.Event)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal envelope event: %w", err)
	}
	switch e := evt.(type) {
	case *eventtypes.ContentCreate:
		dgst := digest.Digest(e.GetDigest())
		refs, err := resilient.RetryValue(ctx, 10, resilient.BackoffDelay(10*time.Millisecond, 100*time.Millisecond), func(ctx context.Context) ([]Reference, error) {
			info, err := c.client.ContentStore().Info(ctx, dgst)
			if err != nil {
				return nil, resilient.Unrecoverable(err)
			}
			refs, err := contentLabelsToReferences(info.Labels, dgst)
			if err != nil {
				return nil, err
			}
			return refs, nil
		})
		if err != nil {
			return nil, err
		}
		events := []OCIEvent{}
		for _, ref := range refs {
			events = append(events, OCIEvent{Type: CreateEvent, Reference: ref})
		}
		return events, nil
	case *eventtypes.ImageCreate:
		img, err := ParseImage(e.GetName(), AllowTagOnly())
		if err != nil {
			return nil, err
		}
		// Just advertise the image if it is a tag reference.
		if img.Digest == "" {
			return []OCIEvent{{Type: CreateEvent, Reference: img.Reference}}, nil
		}
		// Walk the image to index its content.
		cImg, err := c.client.ImageService().Get(ctx, img.String())
		if err != nil {
			return nil, err
		}
		refs := []Reference{}
		descs := map[digest.Digest]ocispec.Descriptor{}
		handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			children, err := images.ChildrenHandler(c.client.ContentStore()).Handle(ctx, desc)
			if errors.Is(err, errdefs.ErrNotFound) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			ref := Reference{
				Registry:   img.Registry,
				Repository: img.Repository,
				Digest:     desc.Digest,
			}
			refs = append(refs, ref)
			descs[desc.Digest] = desc
			return children, nil
		})
		err = images.Walk(ctx, handler, cImg.Target)
		if err != nil {
			return nil, err
		}
		contentIdx[img.Digest] = refs
		// Existence is not checked to keep event handling fast. Blobs which are present
		// in the content store never become complete in the backend and are served from
		// the content store, making their registration harmless.
		c.registerLazyBlobs(refs, descs, nil)
		return nil, nil
	case *eventtypes.ImageDelete:
		img, err := ParseImage(e.GetName(), AllowTagOnly())
		if err != nil {
			return nil, err
		}
		// Just advertise the image if it is a tag reference.
		if img.Digest == "" {
			return []OCIEvent{{Type: DeleteEvent, Reference: img.Reference}}, nil
		}
		// Advertise deletion of images content if it no longer exists.
		refs, ok := contentIdx[img.Digest]
		if !ok {
			logr.FromContextOrDiscard(ctx).Info("delete event with missing content index entry")
			return []OCIEvent{{Type: DeleteEvent, Reference: img.Reference}}, nil
		}
		delete(contentIdx, img.Digest)
		// Delete events are sent before garbage collection is run.
		err = resilient.Retry(ctx, 10, resilient.BackoffDelay(10*time.Millisecond, 100*time.Microsecond), func(ctx context.Context) error {
			_, err := c.client.ContentStore().Info(ctx, img.Digest)
			if errors.Is(err, errdefs.ErrNotFound) {
				return nil
			}
			if err != nil {
				return resilient.Unrecoverable(err)
			}
			return fmt.Errorf("manifest with digest %s still exists", img.Digest.String())
		}, resilient.WithLastErrorOnly())
		if err != nil {
			return nil, fmt.Errorf("image manifest has not been deleted: %w", err)
		}
		// Create delete events for contents that has been removed.
		events := []OCIEvent{}
		for _, ref := range refs {
			c.lazyMu.Lock()
			delete(c.lazyBlobs, ref.Digest)
			c.lazyMu.Unlock()
			_, err := c.client.ContentStore().Info(ctx, ref.Digest)
			if err == nil {
				continue
			}
			if !errors.Is(err, errdefs.ErrNotFound) {
				return nil, err
			}
			events = append(events, OCIEvent{Type: DeleteEvent, Reference: ref})
		}
		return events, nil
	default:
		return nil, errors.New("unsupported event type")
	}
}

func contentLabelsToReferences(l map[string]string, dgst digest.Digest) ([]Reference, error) {
	refs := []Reference{}
	for k, v := range l {
		if !strings.HasPrefix(k, labels.LabelDistributionSource) {
			continue
		}
		ref := Reference{
			Registry:   strings.TrimPrefix(k, labels.LabelDistributionSource+"."),
			Repository: v,
			Digest:     dgst,
		}
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf("no distribution source labels found for %s", dgst)
	}
	return refs, nil
}

// Refer to containerd registry configuration documentation for more information about required configuration.
// https://github.com/containerd/containerd/blob/main/docs/cri/config.md#registry-configuration
// https://github.com/containerd/containerd/blob/main/docs/hosts.md#registry-configuration---examples
func AddMirrorConfiguration(ctx context.Context, configPath string, mirroredRegistries, mirrorTargets []string, resolveTags, prependExisting bool, username, password string) error {
	log := logr.FromContextOrDiscard(ctx)

	// Parse and verify mirror urls.
	parsedMirroredRegistries, err := parseRegistries(mirroredRegistries, true)
	if err != nil {
		return err
	}
	parsedMirrorTargets, err := parseRegistries(mirrorTargets, false)
	if err != nil {
		return err
	}

	// Backup and clear configgurrationn.
	err = os.MkdirAll(configPath, 0o755)
	if err != nil {
		return err
	}
	err = backupConfig(log, configPath)
	if err != nil {
		return err
	}
	err = clearConfig(configPath)
	if err != nil {
		return err
	}

	// Write mirror configuration
	capabilities := []string{"pull"}
	if resolveTags {
		capabilities = append(capabilities, "resolve")
	}
	for _, mr := range parsedMirroredRegistries {
		templatedHosts, err := templateHosts(mr, parsedMirrorTargets, capabilities, username, password)
		if err != nil {
			return err
		}
		if prependExisting {
			existingHosts, err := existingHosts(configPath, mr)
			if err != nil {
				return err
			}
			if existingHosts != "" {
				// If we are prepending we also want to keep files like certificates that may be referenced.
				backupRegDir := path.Join(configPath, backupDir, mr.Host)
				err = filepath.WalkDir(backupRegDir, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					if d.Name() == "hosts.toml" {
						return nil
					}
					src, err := os.Open(path)
					if err != nil {
						return err
					}
					defer src.Close()
					relPath, err := filepath.Rel(backupRegDir, path)
					if err != nil {
						return err
					}
					dstPath := filepath.Join(configPath, mr.Host, relPath)
					err = os.MkdirAll(filepath.Dir(dstPath), 0o755)
					if err != nil {
						return err
					}
					dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
					if err != nil {
						return err
					}
					defer dst.Close()
					_, err = io.Copy(dst, src)
					if err != nil {
						return err
					}
					return nil
				})
				if err != nil {
					return err
				}

				templatedHosts = templatedHosts + "\n\n" + existingHosts
				log.Info("prepending to existing containerd mirror configuration", "registry", mr.String())
			}

		}
		fp := path.Join(configPath, mr.Host, "hosts.toml")
		err = os.MkdirAll(filepath.Dir(fp), 0o755)
		if err != nil {
			return err
		}
		err = os.WriteFile(fp, []byte(templatedHosts), 0o644)
		if err != nil {
			return err
		}
		log.Info("added containerd mirror configuration", "registry", mr.String(), "path", fp)
	}
	return nil
}

func CleanupMirrorConfiguration(ctx context.Context, configPath string) error {
	log := logr.FromContextOrDiscard(ctx)

	// If backup directory does not exist it means mirrors was never configured or cleanup has already run.
	backupDirPath := path.Join(configPath, backupDir)
	ok, err := dirExists(backupDirPath)
	if err != nil {
		return err
	}
	if !ok {
		log.Info("skipping cleanup because backup directory does not exist")
		return nil
	}

	// Remove everything except _backup
	err = clearConfig(configPath)
	if err != nil {
		return err
	}

	// Move content from backup directory
	files, err := os.ReadDir(backupDirPath)
	if err != nil {
		return err
	}
	for _, fi := range files {
		oldPath := path.Join(backupDirPath, fi.Name())
		newPath := path.Join(configPath, fi.Name())
		err := os.Rename(oldPath, newPath)
		if err != nil {
			return err
		}
		log.Info("recovering containerd host configuration", "path", oldPath)
	}

	// Remove backup directory to indicate that cleanup has been run.
	err = os.RemoveAll(backupDirPath)
	if err != nil {
		return err
	}

	return nil
}

func backupConfig(log logr.Logger, configPath string) error {
	backupDirPath := path.Join(configPath, backupDir)
	ok, err := dirExists(backupDirPath)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	files, err := os.ReadDir(configPath)
	if err != nil {
		return err
	}
	err = os.MkdirAll(backupDirPath, 0o755)
	if err != nil {
		return err
	}
	for _, fi := range files {
		oldPath := path.Join(configPath, fi.Name())
		newPath := path.Join(backupDirPath, fi.Name())
		err := os.Rename(oldPath, newPath)
		if err != nil {
			return err
		}
		log.Info("backing up containerd host configuration", "path", oldPath)
	}
	return nil
}

func clearConfig(configPath string) error {
	files, err := os.ReadDir(configPath)
	if err != nil {
		return err
	}
	for _, fi := range files {
		if fi.Name() == backupDir {
			continue
		}
		filePath := path.Join(configPath, fi.Name())
		err := os.RemoveAll(filePath)
		if err != nil {
			return err
		}
	}
	return nil
}

func templateHosts(parsedMirrorRegistry url.URL, parsedMirrorTargets []url.URL, capabilities []string, username, password string) (string, error) {
	server := parsedMirrorRegistry.String()
	if parsedMirrorRegistry.String() == "https://docker.io" {
		server = "https://registry-1.docker.io"
	}
	if parsedMirrorRegistry == wildcardRegistryURL {
		server = ""
	}

	authorization := ""
	if username != "" || password != "" {
		authorization = username + ":" + password
		authorization = base64.StdEncoding.EncodeToString([]byte(authorization))
		authorization = "Basic " + authorization
	}

	hc := struct {
		Authorization string
		Server        string
		Capabilities  string
		MirrorTargets []url.URL
	}{
		Server:        server,
		Capabilities:  fmt.Sprintf("['%s']", strings.Join(capabilities, "', '")),
		MirrorTargets: parsedMirrorTargets,
		Authorization: authorization,
	}
	tmpl, err := template.New("").Parse(`{{- with .Server }}server = '{{ . }}'{{ end }}
{{- $authorization := .Authorization }}
{{ range .MirrorTargets }}
[host.'{{ .String }}']
capabilities = {{ $.Capabilities }}
dial_timeout = '200ms'
{{- if $authorization }}
[host.'{{ .String }}'.header]
Authorization = '{{ $authorization }}'
{{- end }}
{{ end }}`)
	if err != nil {
		return "", err
	}
	buf := bytes.NewBuffer(nil)
	err = tmpl.Execute(buf, hc)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

func existingHosts(configPath string, parsedMirrorRegistry url.URL) (string, error) {
	fp := path.Join(configPath, backupDir, parsedMirrorRegistry.Host, "hosts.toml")
	b, err := os.ReadFile(fp)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	type hostFile struct {
		Hosts map[string]any `toml:"host"`
	}

	var hf hostFile
	err = toml.Unmarshal(b, &hf)
	if err != nil {
		return "", err
	}
	if len(hf.Hosts) == 0 {
		return "", nil
	}

	hosts := []string{}
	parser := tomlu.Parser{}
	parser.Reset(b)
	for parser.NextExpression() {
		err := parser.Error()
		if err != nil {
			return "", err
		}
		e := parser.Expression()
		if e.Kind != tomlu.Table {
			continue
		}
		ki := e.Key()
		if ki.Next() && string(ki.Node().Data) == "host" && ki.Next() && ki.IsLast() {
			hosts = append(hosts, string(ki.Node().Data))
		}
	}

	ehs := []string{}
	for _, h := range hosts {
		data := hostFile{
			Hosts: map[string]any{
				h: hf.Hosts[h],
			},
		}
		b, err := toml.Marshal(data)
		if err != nil {
			return "", err
		}
		eh := strings.TrimPrefix(string(b), "[host]\n")
		ehs = append(ehs, eh)
	}
	return strings.TrimSpace(strings.Join(ehs, "\n")), nil
}

func dirExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}
