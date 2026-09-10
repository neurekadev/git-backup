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
//
// The work splits into three steps with one job each: reject a remote URL this
// package will not talk to, scan the mirror for pointers, settle which endpoint
// serves this repository's LFS API, and then fetch from that endpoint alone.
// Settling the endpoint first is what keeps the fetch simple — no fallback to
// reconcile, and no way for a working endpoint to be mistaken for a missing one
// partway through a repository.
func (f *Fetcher) FetchAll(ctx context.Context, repositoryPath, remoteURL, username, password string) error {
	repository, err := git.PlainOpen(repositoryPath)
	if err != nil {
		return fmt.Errorf("open repository: %w", err)
	}
	parsed, err := parseRemoteURL(remoteURL)
	if err != nil {
		return err
	}

	pointers, err := f.pointers(ctx, repository, remoteURL)
	if err != nil || len(pointers) == 0 {
		return err
	}

	candidates, err := endpointCandidates(repository, parsed)
	if err != nil {
		return err
	}
	endpoint, err := f.selectEndpoint(ctx, candidates, username, password, pointers[0])
	if err != nil {
		return err
	}

	store := objectStoreDir(repository, repositoryPath)
	outcome, err := f.fetchBatches(ctx, store, endpoint, username, password, pointers)
	if err != nil {
		return err
	}
	if outcome.unavailable > 0 {
		// The endpoint serves this repository but does not have every object a
		// pointer names. The mirror keeps what it got; the gap is reported
		// rather than passed over, because a mirror missing LFS content is not a
		// complete backup.
		slog.Warn("Some Git LFS objects could not be fetched; the repository was mirrored without them.",
			"endpoint", redactedURL(endpoint), "objectsMissing", outcome.unavailable, "objectsRequested", len(pointers))
		slog.Debug("Git LFS objects that could not be fetched.",
			"endpoint", redactedURL(endpoint), "reason", outcome.skipped.Error())
		return fmt.Errorf("%d of %d LFS objects could not be fetched: %w",
			outcome.unavailable, len(pointers), outcome.skipped)
	}
	return nil
}

// parseRemoteURL rejects a remote this package will not talk to: only http and
// https are accepted, so a provider-supplied URL can never reach a transport
// helper or a local path.
func parseRemoteURL(remoteURL string) (*url.URL, error) {
	parsed, ok := paths.ParseHTTPURL(remoteURL)
	if !ok {
		return nil, fmt.Errorf("unsupported remote URL '%s': only http and https are allowed", redactedURL(remoteURL))
	}
	return parsed, nil
}

// pointers scans the mirror for the LFS pointers its refs reach, reporting the
// parts of the repository it could not read. A scan that could not read
// everything fails the fetch: a backup reported as complete while content it
// could not scan is silently absent is worse than one that reports what it could
// not do.
func (f *Fetcher) pointers(ctx context.Context, repository *git.Repository, remoteURL string) ([]pointer, error) {
	scan, err := collectPointers(ctx, repository)
	if err != nil {
		return nil, fmt.Errorf("scan for LFS pointers: %w", err)
	}
	if len(scan.skipped) > 0 {
		for _, skipped := range scan.skipped {
			slog.Warn("Could not read part of the repository while scanning for Git LFS pointers.",
				"repository", redactedURL(remoteURL), "entry", skipped.name,
				"oid", shortOID(skipped.hash.String()), "reason", skipped.err.Error())
		}
		return nil, fmt.Errorf("%d entries could not be read while scanning for LFS pointers, so the mirror would be incomplete", len(scan.skipped))
	}
	// Nothing to fetch means the endpoint is never contacted, so a forge without
	// LFS is not mistaken for one that disabled it.
	return scan.pointers, nil
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
func (f *Fetcher) fetchBatches(
	ctx context.Context,
	store, endpoint, username, password string,
	pointers []pointer,
) (chunkOutcome, error) {
	var total chunkOutcome
	var firstErr error
	for start := 0; start < len(pointers); start += batchObjectLimit {
		end := min(start+batchObjectLimit, len(pointers))
		if err := ctx.Err(); err != nil {
			return total, err
		}

		outcome, err := f.fetchChunk(ctx, store, endpoint, username, password, pointers[start:end])
		total.absorb(outcome)
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

	if firstErr != nil {
		return total, firstErr
	}
	if missing := total.unavailable + total.rejected; missing > 0 {
		return total, fmt.Errorf("%d of %d LFS objects could not be fetched: %w", missing, len(pointers), total.skipped)
	}
	return total, nil
}

// chunkOutcome reports what one batch request could not fetch — objects the
// endpoint answered for but will not serve, and objects whose own batch request
// the endpoint rejected outright — and whether it answered for any of them, which
// is what separates a rejection beside real answers from one that stands alone.
// skipped, when set, names the first object that could not be fetched.
type chunkOutcome struct {
	unavailable int
	rejected    int
	answered    bool
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
	// each half narrows further on its own. Both halves are always tried, so a
	// failure in one cannot cost the other its objects, and the pair is what
	// makes the chunk's outcome complete whichever half went wrong.
	if len(pointers) > 1 {
		middle := len(pointers) / 2
		outcome, firstErr := f.fetchChunk(ctx, store, endpoint, username, password, pointers[:middle])
		if firstErr != nil && !isRefusal(firstErr) {
			// A half that failed outright still must not cost its sibling.
			rest, _ := f.fetchChunk(ctx, store, endpoint, username, password, pointers[middle:])
			outcome.absorb(rest)
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
	//
	// The object's own report renders the rejection rather than wrapping it: an
	// error matching both sentinels would read as the endpoint's refusal and as
	// one object's unavailability at once, and callers weigh those differently.
	slog.Debug("Git LFS batch request rejected for a single object.",
		"endpoint", redactedURL(endpoint), "oid", shortOID(pointers[0].oid), "reason", rejection.Error())
	return chunkOutcome{
		rejected: 1,
		skipped: fmt.Errorf("%w: LFS object %s download request rejected: %v",
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
	if outcome.answered || outcome.unavailable > 0 {
		return outcome, nil
	}
	return outcome, fmt.Errorf("%w: %w", errAllRejected, rejection)
}

// downloadChunk streams every object the batch scheduled. Objects the endpoint
// will not serve are recorded and skipped so their siblings still download, and
// so are objects this client could not transfer — attempted, but unreachable —
// which come back as an error once every object has had its turn. The chunk
// counts as answered when the endpoint replied with content for any scheduled
// object, which is what tells a rejection beside real answers from one that
// stands alone.
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
	// The endpoint answered for every object that is not unavailable, whether it
	// streamed the bytes now or found them already in the store. A chunk it
	// answered for is not a chunk it refused, so a rejection beside those answers
	// is one object's fault rather than the endpoint's.
	outcome.answered = len(objects) > len(unavailable)
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
	o.answered = o.answered || half.answered
	if half.skipped != nil && o.skipped == nil {
		o.skipped = half.skipped
	}
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
