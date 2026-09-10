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

	endpoints, err := resolveEndpoints(repository, remoteURL)
	if err != nil {
		return err
	}

	scan, err := collectPointers(ctx, repository)
	if err != nil {
		return fmt.Errorf("scan for LFS pointers: %w", err)
	}
	if len(scan.skipped) > 0 {
		// Whatever those objects held is missing from the mirror, so name them
		// and fail the fetch: a backup reported as complete while LFS content is
		// silently absent is worse than one that reports what it could not do.
		for _, skipped := range scan.skipped {
			slog.Warn("Could not read part of the repository while scanning for Git LFS pointers.",
				"repository", redactedURL(remoteURL), "entry", skipped.name,
				"oid", shortOID(skipped.hash.String()), "reason", skipped.err.Error())
		}
		return fmt.Errorf("%d entries could not be read while scanning for LFS pointers, so the mirror would be incomplete", len(scan.skipped))
	}
	if len(scan.pointers) == 0 {
		// Nothing to fetch; never contact the endpoint so a forge without LFS
		// is not mistaken for one that disabled it.
		return nil
	}
	pointers := scan.pointers

	store := objectStoreDir(repository, repositoryPath)
	var disabledErr, rejectedErr, hardErr error
	for _, endpoint := range endpoints {
		served, endpointErr := f.fetchBatches(ctx, store, endpoint, username, password, pointers)
		if endpointErr == nil {
			return nil
		}
		if served > 0 && !errors.Is(endpointErr, errObjectUnavailable) {
			// An endpoint that already mirrored part of the repository is
			// authoritative whatever it says afterwards: no later verdict —
			// "LFS is off", "nothing here", a rejection — may be recorded as a
			// clean skip, because that would report a half-finished mirror as
			// complete. The outcome is rendered rather than wrapped, so no skip
			// sentinel survives to be matched through the chain.
			if hardErr == nil {
				hardErr = fmt.Errorf("%d LFS objects were fetched before the endpoint stopped serving the rest: %v", served, endpointErr)
			}
			slog.Debug("Endpoint stopped serving partway through the repository.",
				"endpoint", redactedURL(endpoint), "objectsServed", served, "detail", endpointErr.Error())
			continue
		}
		switch {
		case errors.Is(endpointErr, ErrDisabled):
			// A repository with LFS switched off is an expected skip, and the
			// endpoint that said so is the one serving the API.
			if disabledErr == nil {
				disabledErr = endpointErr
			}
		case errors.Is(endpointErr, ErrNoEndpoint):
			// Nothing is mounted at this path; the next candidate may serve it.
		case errors.Is(endpointErr, errBatchRejected):
			if rejectedErr == nil {
				rejectedErr = endpointErr
			}
		default:
			// The candidate that failed may be the derived guess rather than the
			// path the remote configures, so the remaining candidates still get
			// their turn before this is reported.
			if hardErr == nil {
				hardErr = endpointErr
			}
		}
		slog.Debug("No Git LFS service answered at this endpoint.", "endpoint", redactedURL(endpoint))
	}

	switch {
	case hardErr != nil:
		// A real failure on any candidate outranks another's "LFS is off"
		// answer, which the mirror layer records as a successful skip: masking
		// the failure would report an incomplete mirror as complete.
		return hardErr
	case disabledErr != nil:
		// A candidate that answered "LFS is off" identified the API root, so its
		// verdict is authoritative in a way another candidate's request-shape
		// rejection is not.
		return disabledErr
	case rejectedErr != nil:
		return rejectedErr
	default:
		// No candidate served the API, which the mirror layer records as LFS
		// being switched off rather than failing the repository.
		return ErrDisabled
	}
}

// batchObjectLimit is how many pointers one batch request submits. Git LFS
// clients use the same limit; a forge may reject a request that exceeds its own
// smaller limit, which fetchChunk then narrows down.
//
// Narrowing is not remembered between chunks, deliberately. A refusal cannot
// distinguish a server whose limit is low from a chunk carrying one object the
// server will not serve, and a remembered bound derived from the second kind
// would shrink every later chunk — including chunks of perfectly servable
// objects. The cost of not remembering is bounded: at most two requests per
// pointer in a chunk, and the sweep stops after a second failing chunk.
const batchObjectLimit = 100

// ErrNoEndpoint reports that nothing answered the LFS batch API at an endpoint,
// which is how a forge that routes the API elsewhere — or at all — looks to a
// client. FetchAll tries its next candidate endpoint on this answer, and a
// repository with no service anywhere is reported with ErrDisabled, because from
// here that is indistinguishable from LFS being switched off and the mirror
// layer already knows how to record it.
var ErrNoEndpoint = errors.New("no git lfs service answered at the endpoint")

// fetchBatches downloads every pointer's object, splitting the pointers into
// batch requests. A batch the endpoint rejects is narrowed down by halving, so
// one object the server will not serve — a stale pointer, or a request above
// the server's own limit — costs that object alone instead of the repository's
// entire LFS mirror. Failing to mirror an object that exists still errors the
// fetch.
//
// Narrowing a chunk costs up to two requests per pointer in it, not a
// logarithmic count: a half the endpoint answered nothing for may hold nothing
// but individually refused objects, so the only way to know whether its sibling
// is servable is to ask it. A chunk the endpoint answered nothing for therefore
// still reports, and the sweep continues, because that state may mean a broken
// endpoint or merely a chunk of stale pointers. Once a second chunk fails, the
// fetch stops and reports rather than repeating the failure across a large
// repository.
//
// The count of objects the endpoint served comes back with the error, because a
// caller has to know whether an endpoint that now answers "no service" or "LFS
// off" already mirrored part of the repository: a verdict that would mean a
// clean skip cannot also mean a half-finished mirror.
func (f *Fetcher) fetchBatches(
	ctx context.Context,
	store, endpoint, username, password string,
	pointers []pointer,
) (int, error) {
	var unavailable, rejected, served int
	var firstFailure, firstErr error
	for start := 0; start < len(pointers); start += batchObjectLimit {
		end := min(start+batchObjectLimit, len(pointers))
		if err := ctx.Err(); err != nil {
			return served, err
		}

		outcome, err := f.fetchChunk(ctx, store, endpoint, username, password, pointers[start:end])
		unavailable += outcome.unavailable
		rejected += outcome.rejected
		served += outcome.served
		if outcome.skipped != nil && firstFailure == nil {
			firstFailure = outcome.skipped
		}
		if err == nil {
			continue
		}
		// A chunk the endpoint answered nothing for is reported, but the rest of
		// the repository is still attempted: that state may mean a broken
		// endpoint or merely a chunk of stale pointers, and only the next chunk
		// tells them apart.
		if firstErr != nil {
			// The endpoint failed a second chunk, so stop asking.
			slog.Debug("Stopping the Git LFS fetch after another chunk failed.",
				"endpoint", redactedURL(endpoint), "detail", err.Error())
			break
		}
		firstErr = err
	}

	skipped := unavailable + rejected
	if skipped > 0 {
		// The mirrored repository stays usable, but its LFS content is not
		// complete, so say so once per repository at warn level and keep the
		// per-object reasons for debug output.
		slog.Warn("Some Git LFS objects could not be fetched; the repository was mirrored without them.",
			"endpoint", redactedURL(endpoint), "objectsMissing", skipped, "objectsRequested", len(pointers))
		slog.Debug("Git LFS objects that could not be fetched.",
			"endpoint", redactedURL(endpoint), "reason", firstFailure.Error())
	}
	if firstErr != nil {
		return served, firstErr
	}
	if skipped > 0 {
		return served, fmt.Errorf("%d of %d LFS objects could not be fetched: %w", skipped, len(pointers), firstFailure)
	}
	return served, nil
}

// chunkOutcome reports what one batch request could not fetch — objects the
// endpoint answered for but will not serve, and objects whose own batch request
// the endpoint rejected outright — and how many it did serve. skipped, when
// set, names the first object that could not be fetched.
type chunkOutcome struct {
	unavailable int
	rejected    int
	served      int
	skipped     error
}

// errNarrowedToSingleton marks the rejection of a single object's own batch
// request. Callers compare it with a sibling half's outcome to decide whether
// the endpoint refuses the request shape itself or merely that one object.
var errNarrowedToSingleton = errors.New("batch request rejected down to a single object")

// errAllRejected marks a chunk whose every request was refused while the
// endpoint answered none of its objects, which is as close as a client can get to
// an endpoint-wide rejection. It is reported and, once a second chunk repeats it,
// treated as the endpoint being broken rather than as a chunk of stale pointers.
var errAllRejected = errors.New("every request for this batch was rejected")

// fetchChunk submits one batch request for pointers and downloads what it
// schedules. A rejected batch is split in half and resubmitted, down to single
// pointers, so the rejection is narrowed to the object that caused it: a request
// the endpoint considers too large, or one poisonous object, then costs that
// object alone instead of the chunk's whole LFS content.
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
	// Descending calls answer with their own errors, so the rejection that
	// brought us here is kept for the reports below.
	rejection := err

	// A rejected chunk wider than one pointer is retried as two batches, and
	// each half narrows further on its own. The sibling half is always tried,
	// whatever the first half concluded: a half in which the endpoint answered
	// nothing may consist of individually refused objects rather than a refused
	// endpoint, and only the sibling's answer — or its absence — settles which.
	// Trying it is also what lets the sibling's objects reach the mirror when
	// only the first half is poisoned.
	if len(pointers) > 1 {
		middle := len(pointers) / 2
		outcome, firstErr := f.fetchChunk(ctx, store, endpoint, username, password, pointers[:middle])
		if firstErr != nil && !isRefusal(firstErr) {
			return outcome, firstErr
		}

		rest, restErr := f.fetchChunk(ctx, store, endpoint, username, password, pointers[middle:])
		outcome.absorb(rest)
		if restErr != nil && !isRefusal(restErr) {
			return outcome, restErr
		}
		if firstErr == nil && restErr == nil {
			return outcome, nil
		}
		// A rejection reached a single pointer in one of the halves, and the
		// whole chunk is now accounted for, so the rejection can be attributed.
		return refuseOrReport(outcome, rejection)
	}

	// The endpoint refuses this single object's own request, so nothing narrower
	// can be blamed. Whether that is this object's fault or the endpoint's is
	// decided one level up, by whether the sibling half was served; this subtree
	// has served nothing either way.
	slog.Debug("Git LFS batch request rejected for a single object.",
		"endpoint", redactedURL(endpoint), "oid", shortOID(pointers[0].oid), "reason", rejection.Error())
	return chunkOutcome{
		rejected: 1,
		skipped: fmt.Errorf("%w: LFS object %s download request rejected: %w",
			errObjectUnavailable, shortOID(pointers[0].oid), rejection),
	}, fmt.Errorf("%w: %w", errNarrowedToSingleton, rejection)
}

// isRefusal reports whether an error means the endpoint refused a request
// rather than failing to serve it.
func isRefusal(err error) bool {
	return errors.Is(err, errNarrowedToSingleton) || errors.Is(err, errAllRejected)
}

// refuseOrReport settles a chunk whose rejection reached a single pointer. An
// object the endpoint answered for settles it: whether that answer served bytes
// or reported the object missing, the endpoint processed the batch, so a refused
// sibling object is that object's fault rather than the endpoint's. A chunk the
// endpoint answered nothing for is the alternative — allRejected wrapping
// errBatchRejected — which callers report and stop the sweep after, since only a
// second such chunk tells stale pointers apart from a broken endpoint.
func refuseOrReport(outcome chunkOutcome, rejection error) (chunkOutcome, error) {
	if outcome.served > 0 || outcome.unavailable > 0 {
		return outcome, nil
	}
	return outcome, fmt.Errorf("%w: %w", errAllRejected, rejection)
}

// downloadChunk streams every object the batch scheduled. Objects the endpoint
// will not serve are recorded and skipped so their siblings still download, and
// so are objects this client could not transfer — attempted, but unreachable —
// which come back as an error once every object has had its turn.
func (f *Fetcher) downloadChunk(
	ctx context.Context,
	store, endpoint, username, password string,
	objects []batchResponseObject,
) (chunkOutcome, error) {
	unavailable, failed := downloadObjects(ctx, f.client, store, endpoint, username, password, objects)

	var outcome chunkOutcome
	for _, object := range unavailable {
		outcome.recordUnavailable(fmt.Errorf("%w: %s", errObjectUnavailable, object.Error()))
	}
	// Whatever the endpoint did not refuse, it answered for one way or another.
	outcome.served = len(objects) - len(unavailable)
	if len(failed) > 0 {
		return outcome, fmt.Errorf("%d of %d LFS objects could not be downloaded: %w", len(failed), len(objects), failed[0])
	}
	return outcome, nil
}

// recordUnavailable counts one object the endpoint answered for but will not
// serve, keeping the first reason for the caller's report.
func (o *chunkOutcome) recordUnavailable(reason error) {
	o.unavailable++
	if o.skipped == nil {
		o.skipped = reason
	}
}

// absorb adds a split's second half to its first.
func (o *chunkOutcome) absorb(half chunkOutcome) {
	o.unavailable += half.unavailable
	o.rejected += half.rejected
	o.served += half.served
	if half.skipped != nil && o.skipped == nil {
		o.skipped = half.skipped
	}
}

// resolveEndpoints determines the LFS API roots to try, in order: an lfs.url
// override from the repository's committed .lfsconfig when present, otherwise
// the remote URL's standard /info/lfs root with and without the repository's
// .git suffix.
//
// The batch request authenticates with the remote's credential, so an override
// is honored only when it is an absolute http(s) URL on the remote's own host
// and scheme — a hostile .lfsconfig must not redirect that credential elsewhere
// or downgrade it to plaintext. Reading .lfsconfig is best-effort — any failure
// falls back to the derived endpoints, matching the common deployment.
func resolveEndpoints(repository *git.Repository, remoteURL string) ([]string, error) {
	parsed, ok := paths.ParseHTTPURL(remoteURL)
	if !ok {
		return nil, fmt.Errorf("unsupported remote URL '%s': only http and https are allowed", redactedURL(remoteURL))
	}

	config, err := readLFSConfig(repository)
	if err == nil && config != nil {
		if override := strings.TrimSpace(config.Raw.Section("lfs").Option("url")); override != "" {
			overridden, ok := paths.ParseHTTPURL(override)
			if !ok {
				return nil, fmt.Errorf("unsupported lfs.url '%s': only absolute http and https URLs are allowed", redactedURL(override))
			}
			if !strings.EqualFold(overridden.Scheme, parsed.Scheme) || canonicalHost(overridden) != canonicalHost(parsed) {
				return nil, fmt.Errorf("refusing lfs.url '%s': the override must stay on the remote host and scheme so the remote credential is not sent elsewhere", redactedURL(override))
			}
			// Drop a redundant scheme-default port so the endpoint is canonical:
			// object-download host comparisons and logs then match hrefs rendered
			// without the explicit port.
			if overridden.Port() != "" && isSchemeDefaultPort(overridden) {
				overridden.Host = strings.TrimSuffix(overridden.Host, ":"+overridden.Port())
			}
			return []string{strings.TrimSuffix(overridden.String(), "/")}, nil
		}
	}
	// A remote that already carries the repository suffix, or has no path at
	// all, reaches the API at one path, so there is nothing to fall back to:
	// probing the same URL twice would only repeat every request.
	suffixed, plain := defaultEndpoint(parsed), plainEndpoint(parsed)
	if suffixed == plain {
		return []string{suffixed}, nil
	}
	return []string{suffixed, plain}, nil
}

// defaultEndpoint derives the remote's standard LFS API root, including the
// repository's .git suffix.
//
// Git LFS clients request "<remote>[/info/lfs]" with the suffix their remote
// uses, and forges route only the suffixed path to their LFS service: GitHub
// and GitLab answer a suffix-less /info/lfs with 422, while Forgejo and Gitea
// accept either form. The mirror's remote has no .git suffix because a config
// URL rarely carries one, so the suffix is added here whenever it is absent;
// plainEndpoint is the fallback for a service that routes the suffix-less path.
//
// The parsed URL is copied and only its path rewritten, from its escaped form so
// percent-encoding survives: a remote whose path holds a reserved byte — an
// encoded slash in a repository name, say — must keep requesting that exact
// path. Everything else the configured remote carries, userinfo for a deployment
// that embeds credentials and a non-default port among it, still reaches the
// endpoint. A remote with no path has no repository to suffix, but the API root
// is still /info/lfs on that host.
func defaultEndpoint(remoteURL *url.URL) string {
	endpoint := endpointBase(remoteURL)

	escaped := strings.TrimSuffix(remoteURL.EscapedPath(), "/")
	if escaped == "" {
		// No repository segment to suffix, but the API root is still /info/lfs
		// on that host.
		return withPath(endpoint, "/info/lfs")
	}
	// The suffix is judged on the decoded path but appended to the escaped one,
	// so a remote whose escaping hides it (re%2Egit) is not given a second
	// suffix it did not need. It is matched case-insensitively, as the mirror's
	// other .git handling does: a remote already ending in ".GIT" must not gain
	// a differently cased one that no forge serves.
	if !hasGitSuffix(strings.TrimSuffix(remoteURL.Path, "/")) {
		escaped += ".git"
	}
	return withPath(endpoint, escaped+"/info/lfs")
}

// plainEndpoint derives the LFS API root at the remote's configured path,
// without adding the repository suffix: the fallback for a service that routes
// /info/lfs exactly where the remote points.
func plainEndpoint(remoteURL *url.URL) string {
	endpoint := endpointBase(remoteURL)
	return withPath(endpoint, strings.TrimSuffix(remoteURL.EscapedPath(), "/")+"/info/lfs")
}

// endpointBase copies a remote URL with the parts an API root cannot carry
// removed: a query, a forced empty query, and a fragment would otherwise sit
// between the endpoint and the action path appended to it.
func endpointBase(remoteURL *url.URL) url.URL {
	endpoint := *remoteURL
	endpoint.RawQuery = ""
	endpoint.ForceQuery = false
	endpoint.Fragment = ""
	endpoint.RawFragment = ""
	return endpoint
}

// withPath points an endpoint at an escaped path, keeping Path decoded so
// String() does not escape the escaping a second time.
func withPath(endpoint url.URL, escaped string) string {
	endpoint.RawPath = escaped
	endpoint.Path, _ = url.PathUnescape(escaped)
	return endpoint.String()
}

// hasGitSuffix reports whether a remote path already ends in the repository
// suffix, in any case.
func hasGitSuffix(path string) bool {
	return len(path) >= len(".git") && strings.EqualFold(path[len(path)-len(".git"):], ".git")
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
