// Package git maintains bare mirror clones of repositories on local disk.
//
// The whole daemon's clone-and-fetch traffic flows through this package. Only
// http/https transports are accepted, so a provider-supplied URL can never
// reach a transport helper such as ext:: or file://, which would run commands
// or read local files.
package git

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/neurekadev/git-backup/internal/lfs"
	"github.com/neurekadev/git-backup/internal/paths"
)

// Credential is an HTTP basic-auth pair for one forge remote. Forges match on
// the token and ignore the username.
type Credential struct {
	Username string
	Password string
}

// RemoteInaccessibleError marks a remote that cannot be accessed: it is
// private, was removed, or the credentials in play do not grant access. This
// is an expected per-repository condition, so callers skip the repository with
// a warning while genuine git failures still error the run.
type RemoteInaccessibleError struct {
	Err error
}

func (e *RemoteInaccessibleError) Error() string { return e.Err.Error() }
func (e *RemoteInaccessibleError) Unwrap() error { return e.Err }

// RepositoryService mirrors bare repositories into the working root.
type RepositoryService struct {
	lfs *lfs.Fetcher
}

// NewRepositoryService returns the mirror service.
func NewRepositoryService() *RepositoryService {
	return &RepositoryService{lfs: lfs.NewFetcher()}
}

// SyncBareRepository mirrors remoteURL into the bare repository at localPath.
//
// With cache and an existing mirror, the mirror is updated incrementally; a
// failed update self-heals by re-cloning from scratch so a cached repository
// can never get permanently stuck. With includeLFS, the repository's Git LFS
// objects are fetched for all refs.
func (s *RepositoryService) SyncBareRepository(ctx context.Context, remoteURL, localPath string, credential *Credential, cache, includeLFS bool) error {
	if _, ok := paths.ParseHTTPURL(remoteURL); !ok {
		return fmt.Errorf("unsupported repository URL '%s'. Only http and https clone URLs are allowed.", remoteURL)
	}

	syncedURL := remoteURL
	err := mirrorRepository(ctx, remoteURL, localPath, credential, cache)
	// A host may serve the modern protocol on one form of a repository URL and
	// the older one on the other, and this client cannot read the modern one.
	// The same repository is then reachable at the other form, so a failure
	// that is only about the protocol is retried there rather than reported.
	// The retry becomes the URL the rest of the sync uses, so a host that
	// serves LFS on the answered form only is not failed after the mirror
	// succeeded.
	if alternate := versionTwoAlternate(remoteURL, err); alternate != "" {
		slog.Info("Remote answered with Git protocol v2, which this client cannot read; retrying the other URL form.",
			"repository", paths.RedactURL(remoteURL), "retrying", paths.RedactURL(alternate))
		if err = mirrorRepository(ctx, alternate, localPath, credential, cache); err == nil {
			syncedURL = alternate
		}
	}
	if err != nil {
		return err
	}

	if includeLFS {
		return s.fetchLFS(ctx, syncedURL, localPath, credential)
	}
	return nil
}

// mirrorRepository clones or updates the mirror at localPath from remoteURL.
func mirrorRepository(ctx context.Context, remoteURL, localPath string, credential *Credential, cache bool) error {
	if cache && isBareRepository(localPath) {
		// Update the existing mirror. The mirror refspec (+refs/*:refs/*)
		// force-updates rewritten branches and prune drops refs deleted
		// upstream, so the mirror tracks the remote exactly.
		if err := fetchMirror(ctx, remoteURL, localPath, credential); err != nil {
			if ctx.Err() != nil || isProtocolVersionTwo(err) {
				// A shutdown or a protocol v2 advertisement is not a corrupt
				// mirror. Re-cloning would delete a mirror that is intact — and
				// on the protocol path it would delete the mirror and then fail
				// on the same form, turning a retry that could have fetched
				// incrementally into a full clone.
				return err
			}
			slog.Warn("Incremental mirror fetch failed; re-cloning from scratch.",
				"localPath", localPath, "error", err.Error())
			return freshClone(ctx, remoteURL, localPath, credential)
		}
		return nil
	}
	return freshClone(ctx, remoteURL, localPath, credential)
}

// pktLineTooShort and cannotReadHash are the two fragments go-git's v0/v1 ref
// decoder produces when it is handed a protocol v2 advertisement: the version
// announcement is read as a ref, and "version 2" is too short to be a hash.
// Both are required so an unrelated decode failure cannot be mistaken for it.
//
// The failure is recognised by its text because go-git raises it from deep
// inside the decoder and wraps it in no error this package can match on; there
// is no sentinel to compare against.
const (
	pktLineTooShort = "pkt-line too short"
	cannotReadHash  = "cannot read hash"
)

// versionTwoAlternate returns the other spelling of remoteURL when err says the
// remote answered with a protocol v2 advertisement, and "" when there is
// nothing to retry.
//
// A host decides whether a repository is served at its bare path or at the path
// ending in ".git", and some hosts answer one of the two with the modern
// protocol only. Since go-git v5 cannot read that protocol, the other form is
// the same repository reached a way this client understands. A URL with no path
// to alternate has nothing to offer, so it is reported rather than retried.
func versionTwoAlternate(remoteURL string, err error) string {
	if err == nil || !isProtocolVersionTwo(err) {
		return ""
	}
	return alternateURLForm(remoteURL)
}

func isProtocolVersionTwo(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, cannotReadHash) && strings.Contains(message, pktLineTooShort)
}

// alternateURLForm returns remoteURL with its ".git" suffix flipped, or "" when
// there is no path to flip.
//
// The suffix is matched case-insensitively, as the rest of the codebase does, so
// a URL that already ends in ".GIT" is recognised as suffixed rather than given
// a second one. A trailing slash is normalised away first, because otherwise it
// would end up inside the rewritten path. A fragment is dropped: it is a
// client-side marker that never forms part of what is fetched, and carrying it
// onto the other form would append it to a request the server never sent one
// for. A query is kept, since it can be part of what the remote is asked for.
//
// The rewrite is driven by the decoded path, so an escaped separator is no
// longer distinguished from a real one. A repository path containing a literal
// slash cannot be spelled in a git URL anyway — the separator is structural —
// so decoding is the more faithful reading of the URL, not a loss.
func alternateURLForm(remoteURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(remoteURL))
	if err != nil {
		return ""
	}

	withoutSlash := strings.TrimSuffix(parsed.Path, "/")
	if withoutSlash == "" {
		return ""
	}

	parsed.Path = paths.TrimGitSuffix(withoutSlash)
	if parsed.Path == withoutSlash {
		parsed.Path += ".git"
	}
	parsed.Fragment = ""

	return parsed.String()
}

// fetchLFS mirrors the remote's LFS objects. A remote can have Git LFS turned
// off entirely, in which case the batch API declines; that is an expected
// state, not a backup failure — the repository simply has no LFS objects to
// mirror — so record it as skipped and let the rest of the snapshot proceed.
func (s *RepositoryService) fetchLFS(ctx context.Context, remoteURL, localPath string, credential *Credential) error {
	username, password := "", ""
	if credential != nil {
		username, password = credential.Username, credential.Password
	}

	err := s.lfs.FetchAll(ctx, localPath, remoteURL, username, password)
	if errors.Is(err, lfs.ErrDisabled) {
		slog.Info("Skipped Git LFS fetch because it is disabled on the remote.", "repository", paths.RedactURL(remoteURL))
		return nil
	}
	if err != nil {
		return fmt.Errorf("LFS fetch failed: %w", err)
	}
	return nil
}

func freshClone(ctx context.Context, remoteURL, localPath string, credential *Credential) error {
	if err := os.RemoveAll(localPath); err != nil {
		return fmt.Errorf("remove stale mirror: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return fmt.Errorf("create mirror directory: %w", err)
	}

	_, err := git.PlainCloneContext(ctx, localPath, true, &git.CloneOptions{
		URL:    remoteURL,
		Auth:   basicAuth(credential),
		Mirror: true,
	})
	if err != nil {
		return classify(err)
	}
	return nil
}

func fetchMirror(ctx context.Context, remoteURL, localPath string, credential *Credential) error {
	repository, err := git.PlainOpen(localPath)
	if err != nil {
		return fmt.Errorf("open mirror: %w", err)
	}

	if err := ensureOrigin(repository, remoteURL); err != nil {
		return fmt.Errorf("update origin: %w", err)
	}

	remote, err := repository.Remote("origin")
	if err != nil {
		return fmt.Errorf("open origin remote: %w", err)
	}

	err = remote.FetchContext(ctx, &git.FetchOptions{
		RefSpecs: []gitconfig.RefSpec{"+refs/*:refs/*"},
		Prune:    true,
		Force:    true,
		Tags:     git.AllTags,
		Auth:     basicAuth(credential),
	})
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil
	}
	if err != nil {
		return classify(err)
	}
	return nil
}

// ensureOrigin rewrites the mirror's origin remote whenever its URL or mirror
// refspec does not match the configured remote, so a cached mirror follows the
// settings even if the clone URL changed.
func ensureOrigin(repository *git.Repository, remoteURL string) error {
	config, err := repository.Config()
	if err != nil {
		return err
	}

	existing := config.Remotes["origin"]
	if existing != nil && existing.Mirror && len(existing.URLs) == 1 && existing.URLs[0] == remoteURL {
		return nil
	}

	if existing != nil {
		if err := repository.DeleteRemote("origin"); err != nil {
			return err
		}
	}
	_, err = repository.CreateRemote(&gitconfig.RemoteConfig{
		Name:   "origin",
		URLs:   []string{remoteURL},
		Fetch:  []gitconfig.RefSpec{"+refs/*:refs/*"},
		Mirror: true,
	})
	return err
}

// isBareRepository reports whether localPath holds an existing bare git
// repository usable as an incremental mirror.
func isBareRepository(localPath string) bool {
	info, err := os.Stat(localPath)
	if err != nil || !info.IsDir() {
		return false
	}

	repository, err := git.PlainOpen(localPath)
	if err != nil {
		return false
	}
	config, err := repository.Config()
	if err != nil {
		return false
	}
	return config.Core.IsBare
}

// classify maps go-git's structured transport errors onto the inaccessible
// remote signal: private or removed repositories and wrong or missing
// credentials. Genuine failures (DNS, TLS, connection refused, corruption,
// transfer errors) match none of these and stay errors.
func classify(err error) error {
	if errors.Is(err, transport.ErrAuthenticationRequired) ||
		errors.Is(err, transport.ErrAuthorizationFailed) ||
		errors.Is(err, transport.ErrRepositoryNotFound) {
		return &RemoteInaccessibleError{Err: err}
	}
	return err
}

func basicAuth(credential *Credential) transport.AuthMethod {
	if credential == nil {
		return nil
	}
	username := credential.Username
	if username == "" {
		username = "git"
	}
	return &githttp.BasicAuth{Username: username, Password: credential.Password}
}
