// Package lfs fetches a repository's Git LFS objects for all refs into the
// standard local cache layout, mirroring what `git lfs fetch --all` does for
// the git command-line suite.
//
// The flow is the LFS batch protocol: scan every ref's trees for pointer
// blobs, POST them to the endpoint's objects/batch action, then stream each
// object's download into .git/lfs/objects (or lfs/objects for bare
// repositories) while verifying its SHA-256.
package lfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/neurekadev/git-backup/internal/paths"
)

// ErrDisabled reports that the remote has Git LFS turned off entirely, which is
// an expected state rather than a backup failure.
var ErrDisabled = errors.New("git lfs is disabled on the remote")

// lfsConfigMaxBytes bounds how much of a .lfsconfig file is read; real
// configuration files are a few hundred bytes.
const lfsConfigMaxBytes = 64 * 1024

// Fetcher downloads LFS objects into a local repository's cache.
type Fetcher struct {
	client *batchClient
}

// NewFetcher returns an LFS fetcher using the default HTTP client.
func NewFetcher() *Fetcher {
	return &Fetcher{client: newBatchClient(nil)}
}

// FetchAll fetches every LFS object reachable from the repository's refs at
// repositoryPath, using remoteURL to derive the LFS endpoint. username and
// password authenticate the batch request only; object downloads use the
// server-provided (typically pre-signed) URLs.
func (f *Fetcher) FetchAll(ctx context.Context, repositoryPath, remoteURL, username, password string) error {
	repository, err := git.PlainOpen(repositoryPath)
	if err != nil {
		return fmt.Errorf("open repository: %w", err)
	}

	endpoint, err := resolveEndpoint(repository, remoteURL)
	if err != nil {
		return err
	}

	pointers, err := collectPointers(ctx, repository)
	if err != nil {
		return fmt.Errorf("scan for LFS pointers: %w", err)
	}
	if len(pointers) == 0 {
		// Nothing to fetch; never contact the endpoint so a forge without LFS
		// is not mistaken for one that disabled it.
		return nil
	}

	store := objectStoreDir(repository, repositoryPath)
	return f.fetchBatches(ctx, store, endpoint, username, password, pointers)
}

// batchObjectLimit is how many pointers one batch request submits. Git LFS
// clients use the same limit; a forge may reject a request that exceeds its own
// smaller limit, which fetchChunk then narrows down.
const batchObjectLimit = 100

// fetchBatches downloads every pointer's object, splitting the pointers into
// batch requests. A batch the endpoint rejects is narrowed down object by
// object, so one object the server will not serve — a stale pointer, or a
// request the server considers too large — costs that object alone instead of
// the repository's entire LFS mirror. Failing to mirror an object that exists
// still errors the fetch.
func (f *Fetcher) fetchBatches(
	ctx context.Context,
	store, endpoint, username, password string,
	pointers []pointer,
) error {
	var unavailable, rejected int
	var firstFailure, firstErr error
	for start := 0; start < len(pointers); start += batchObjectLimit {
		end := min(start+batchObjectLimit, len(pointers))
		if err := ctx.Err(); err != nil {
			return err
		}

		outcome, err := f.fetchChunk(ctx, store, endpoint, username, password, pointers[start:end])
		unavailable += outcome.unavailable
		rejected += outcome.rejected
		if outcome.skipped != nil && firstFailure == nil {
			firstFailure = outcome.skipped
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	skipped := unavailable + rejected
	if skipped > 0 {
		// The mirrored repository stays usable, but its LFS content is not
		// complete, so say so once per repository at warn level and keep the
		// per-object reasons for debug output.
		slog.Warn("Some Git LFS objects could not be fetched; the repository was mirrored without them.",
			"endpoint", endpoint, "objectsMissing", skipped, "objectsRequested", len(pointers))
		slog.Debug("Git LFS objects that could not be fetched.",
			"endpoint", endpoint, "reason", firstFailure.Error())
	}
	if firstErr != nil {
		return firstErr
	}
	if skipped > 0 {
		return fmt.Errorf("%d of %d LFS objects could not be fetched: %w", skipped, len(pointers), firstFailure)
	}
	return nil
}

// chunkOutcome reports what one batch request could not fetch: objects the
// endpoint answered for but will not serve, and objects whose own batch request
// the endpoint rejected outright. skipped, when set, names the first of them.
type chunkOutcome struct {
	unavailable int
	rejected    int
	skipped     error
}

// fetchChunk submits one batch request for pointers and downloads what it
// schedules. A rejected batch falls back to requesting the same pointers
// individually: the rejection is usually one poisonous object, and the remaining
// objects then still reach the mirror. A rejection covering more than half of the
// chunk comes back as an error, because a failure that broad is the endpoint's,
// not one object's.
func (f *Fetcher) fetchChunk(
	ctx context.Context,
	store, endpoint, username, password string,
	pointers []pointer,
) (chunkOutcome, error) {
	objects, err := f.client.batch(ctx, endpoint, username, password, pointers)
	if err == nil {
		return f.downloadChunk(ctx, store, endpoint, username, password, objects)
	}
	if !errors.Is(err, errBatchRejected) {
		return chunkOutcome{}, err
	}

	outcome := chunkOutcome{}
	for index := range pointers {
		if ctx.Err() != nil {
			return outcome, ctx.Err()
		}

		single, err := f.client.batch(ctx, endpoint, username, password, pointers[index:index+1])
		if err != nil {
			if !errors.Is(err, errBatchRejected) {
				return outcome, err
			}
			// This object's own request was rejected too, so the endpoint
			// refuses to serve it at all.
			outcome.rejected++
			if outcome.skipped == nil {
				outcome.skipped = fmt.Errorf("%w: LFS object %s download request rejected: %w", errObjectUnavailable, shortOID(pointers[index].oid), err)
			}
			continue
		}

		served, err := f.downloadChunk(ctx, store, endpoint, username, password, single)
		outcome.unavailable += served.unavailable
		outcome.rejected += served.rejected
		if outcome.skipped == nil {
			outcome.skipped = served.skipped
		}
		if err != nil {
			return outcome, err
		}
	}

	if outcome.rejected > len(pointers)/2 {
		return outcome, fmt.Errorf("batch request rejected for %d of %d objects: %w", outcome.rejected, len(pointers), err)
	}
	return outcome, nil
}

// downloadChunk streams every object the batch scheduled. An object the endpoint
// refuses to serve is recorded and skipped so its siblings still reach the
// mirror; any other failure — a corrupt download, a broken connection — comes
// back as an error.
func (f *Fetcher) downloadChunk(
	ctx context.Context,
	store, endpoint, username, password string,
	objects []batchResponseObject,
) (chunkOutcome, error) {
	var outcome chunkOutcome
	for _, object := range objects {
		if object.Error != nil {
			outcome.unavailable++
			if outcome.skipped == nil {
				outcome.skipped = fmt.Errorf("%w: LFS object %s is unavailable: %s",
					errObjectUnavailable, shortOID(object.OID), object.Error.Message)
			}
			continue
		}
		if err := downloadObjects(ctx, f.client, store, endpoint, username, password, []batchResponseObject{object}); err != nil {
			return outcome, err
		}
	}
	return outcome, nil
}

// resolveEndpoint determines the LFS API root: an lfs.url override from the
// repository's committed .lfsconfig when present, otherwise the remote URL's
// standard /info/lfs root. The batch request authenticates with the remote's
// credential, so an override is honored only when it is an absolute http(s)
// URL on the remote's own host and scheme — a hostile .lfsconfig must not
// redirect that credential elsewhere or downgrade it to plaintext. Reading
// .lfsconfig is best-effort — any failure falls back to the derived endpoint,
// matching the common deployment.
func resolveEndpoint(repository *git.Repository, remoteURL string) (string, error) {
	parsed, ok := paths.ParseHTTPURL(remoteURL)
	if !ok {
		return "", fmt.Errorf("unsupported remote URL '%s': only http and https are allowed", redactedURL(remoteURL))
	}
	endpoint := defaultEndpoint(parsed)

	config, err := readLFSConfig(repository)
	if err != nil || config == nil {
		return endpoint, nil
	}
	if override := strings.TrimSpace(config.Raw.Section("lfs").Option("url")); override != "" {
		overridden, ok := paths.ParseHTTPURL(override)
		if !ok {
			return "", fmt.Errorf("unsupported lfs.url '%s': only absolute http and https URLs are allowed", redactedURL(override))
		}
		if !strings.EqualFold(overridden.Scheme, parsed.Scheme) || canonicalHost(overridden) != canonicalHost(parsed) {
			return "", fmt.Errorf("refusing lfs.url '%s': the override must stay on the remote host and scheme so the remote credential is not sent elsewhere", redactedURL(override))
		}
		// Drop a redundant scheme-default port so the endpoint is canonical:
		// object-download host comparisons and logs then match hrefs rendered
		// without the explicit port.
		if overridden.Port() != "" && isSchemeDefaultPort(overridden) {
			overridden.Host = strings.TrimSuffix(overridden.Host, ":"+overridden.Port())
		}
		return strings.TrimSuffix(overridden.String(), "/"), nil
	}
	return endpoint, nil
}

// defaultEndpoint derives the remote's standard LFS API root, including the
// repository's .git suffix.
//
// Git LFS clients request "<remote>[/info/lfs]" with the suffix their remote
// uses, and forges route only the suffixed path to their LFS service: GitHub
// and GitLab answer a suffix-less /info/lfs with 422, while Forgejo and Gitea
// accept either form. The mirror's remote has no .git suffix because a config
// URL rarely carries one, so the suffix is added here whenever it is absent.
func defaultEndpoint(remoteURL *url.URL) string {
	path := strings.TrimSuffix(remoteURL.Path, "/")
	if !strings.HasSuffix(path, ".git") {
		path += ".git"
	}
	return remoteURL.Scheme + "://" + remoteURL.Host + path + "/info/lfs"
}

// isSchemeDefaultPort reports whether the URL's explicit port equals its
// scheme's default (http 80, https 443).
func isSchemeDefaultPort(u *url.URL) bool {
	return (strings.EqualFold(u.Scheme, "http") && u.Port() == "80") ||
		(strings.EqualFold(u.Scheme, "https") && u.Port() == "443")
}

// canonicalHost renders the URL's host lowercased with any scheme-default
// port removed, so an explicit https://host:443 compares equal to
// https://host while a redirect to any other port stays distinct.
func canonicalHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || isSchemeDefaultPort(u) {
		return host
	}
	return host + ":" + port
}

// redactedURL renders a URL with any embedded password masked, for safe
// inclusion in error messages.
func redactedURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return rawURL
	}
	return parsed.Redacted()
}

func readLFSConfig(repository *git.Repository) (*config.Config, error) {
	head, err := repository.Head()
	if err != nil {
		return nil, err
	}
	commit, err := repository.CommitObject(head.Hash())
	if err != nil {
		return nil, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	file, err := tree.File(".lfsconfig")
	if err != nil {
		return nil, err
	}
	reader, err := file.Reader()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	content, err := io.ReadAll(io.LimitReader(reader, lfsConfigMaxBytes))
	if err != nil {
		return nil, err
	}
	return config.ReadConfig(bytes.NewReader(content))
}

// objectStoreDir mirrors git-lfs' cache location: a bare repository stores LFS
// objects under its own root, a working copy under .git/lfs.
func objectStoreDir(repository *git.Repository, repositoryPath string) string {
	config, err := repository.Config()
	if err == nil && !config.Core.IsBare {
		return filepath.Join(repositoryPath, ".git", "lfs", "objects")
	}
	return filepath.Join(repositoryPath, "lfs", "objects")
}
