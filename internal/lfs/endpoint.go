package lfs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/neurekadev/git-backup/internal/paths"
)

// endpointCandidates lists, in the order they should be asked, the API roots a
// repository's LFS objects may live under: an lfs.url override from the
// repository's committed .lfsconfig when present, otherwise the remote URL's
// standard /info/lfs root with and without the repository's .git suffix.
//
// Which of the derived roots answers is a property of the host, and no rule
// decides it: GitHub and GitLab route only the suffixed path to their LFS
// service and answer a suffix-less /info/lfs with 422, while a host may mount
// the service exactly where its remote points. The distinction is therefore
// settled by asking, once, before any object is fetched — see selectEndpoint.
//
// The batch request authenticates with the remote's credential, so an override
// is honored only when it is an absolute http(s) URL on the remote's own host
// and scheme: a hostile .lfsconfig must not redirect that credential elsewhere
// or downgrade it to plaintext. Reading .lfsconfig is best-effort — any failure
// falls back to the derived candidates, matching the common deployment.
// endpointCandidate is one API root worth asking, and whether this package
// derived it rather than taking it from the configured remote.
//
// The distinction decides how much an answer weighs. A path the remote actually
// points at is the repository's own root, so its verdict speaks for the
// repository; a derived path is a guess about how the host routes LFS, and a
// guess answering "LFS is off" is weaker evidence than a real failure on the
// path the remote configures.
type endpointCandidate struct {
	url string
	// derived marks the suffixed root this package adds when the configured
	// remote does not carry one.
	derived bool
}

// endpointCandidates lists, in the order they should be asked, the API roots a
// repository's LFS objects may live under: an lfs.url override from the
// repository's committed .lfsconfig when present, otherwise the remote URL's
// standard /info/lfs root with and without the repository's .git suffix.
//
// Which of the derived roots answers is a property of the host, and no rule
// decides it: GitHub and GitLab route only the suffixed path to their LFS
// service and answer a suffix-less /info/lfs with 422, while a host may mount
// the service exactly where its remote points. The distinction is therefore
// settled by asking, once, before any object is fetched — see selectEndpoint.
//
// The batch request authenticates with the remote's credential, so an override
// is honored only when it is an absolute http(s) URL on the remote's own host
// and scheme: a hostile .lfsconfig must not redirect that credential elsewhere
// or downgrade it to plaintext. Reading .lfsconfig is best-effort — any failure
// falls back to the derived candidates, matching the common deployment.
func endpointCandidates(repository *git.Repository, parsed *url.URL) ([]endpointCandidate, error) {
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
			// An override's own query, forced query, and fragment cannot ride
			// along: the action path is appended to the endpoint, so anything
			// after the path would land in the middle of the request line.
			cleaned := endpointBase(overridden)
			return []endpointCandidate{{url: strings.TrimSuffix(cleaned.String(), "/")}}, nil
		}
	}

	// A remote that already carries the repository suffix, or has no path at
	// all, reaches the API at one path, so there is nothing to choose between.
	suffixed, plain := suffixedEndpoint(parsed), plainEndpoint(parsed)
	if suffixed == plain {
		return []endpointCandidate{{url: suffixed}}, nil
	}
	// The configured remote's own path is asked second only because a forge that
	// requires the suffix is the more common deployment; it is not the weaker
	// candidate.
	return []endpointCandidate{{url: suffixed, derived: true}, {url: plain}}, nil
}

// selectEndpoint answers which candidate serves this repository's LFS API, by
// asking each one for a single object before anything is downloaded.
//
// Asking first is what keeps the fetch itself simple: a probe separates the
// answers a host can give — the API answered for the object, LFS is switched
// off, nothing is mounted at that path, or the endpoint failed — so the fetch
// then runs against one known-good endpoint with no fallback to reconcile.
//
// Every candidate is asked, and what decides the repository is the answer from
// the path the remote itself configures. A derived guess never overrides that
// path's answer in either direction: a guess reporting "LFS is off" must not mask
// a credential, rate-limit, server, or transport failure on the configured path
// — the mirror layer records disabled as a successful skip, so that would mirror
// the repository with no LFS content and raise nothing — and a guess failing must
// not turn a configured path's "LFS is off" into a failed backup. The guess only
// decides when the configured path said nothing itself, which is the case it
// exists for: a host that routes LFS solely under the suffixed path.
func (f *Fetcher) selectEndpoint(
	ctx context.Context,
	candidates []endpointCandidate,
	creds credentials,
	first pointer,
) (string, error) {
	var configured, derived error
	for _, candidate := range candidates {
		switch err := f.client.probe(ctx, candidate.url, creds, first); {
		case err == nil:
			slog.Debug("Git LFS API answered.", "endpoint", redactedURL(candidate.url))
			return candidate.url, nil
		case errors.Is(err, ErrDisabled):
			slog.Debug("Git LFS is switched off for this repository.", "endpoint", redactedURL(candidate.url))
			if candidate.derived {
				if derived == nil {
					derived = err
				}
			} else if configured == nil {
				configured = err
			}
		case errors.Is(err, ErrNoEndpoint):
			slog.Debug("No Git LFS API is mounted at this endpoint.", "endpoint", redactedURL(candidate.url))
		default:
			// The endpoint and the error both describe URLs, and the error's own
			// text repeats the one the request went to, so it is redacted too
			// before it reaches the log.
			slog.Debug("Git LFS API did not answer.",
				"endpoint", redactedURL(candidate.url), "detail", redactedURL(err.Error()))
			if candidate.derived {
				if derived == nil {
					derived = err
				}
			} else if configured == nil {
				configured = err
			}
		}
	}

	if configured != nil {
		if derived != nil {
			// The guess's answer is kept for the debug trail rather than
			// discarded — it is just not what decides the fetch.
			slog.Debug("The derived path answered differently from the configured one.",
				"detail", redactedURL(derived.Error()))
		}
		return "", configured
	}
	if derived != nil {
		return "", derived
	}
	// No candidate serves the API. The mirror layer records that as LFS being
	// switched off rather than failing the repository, which is the closest
	// truthful reading available from a client.
	return "", ErrDisabled
}

// suffixedEndpoint derives the remote's standard LFS API root, including the
// repository's .git suffix.
//
// The parsed URL is copied and only its path rewritten, from its escaped form so
// percent-encoding survives: a remote whose path holds a reserved byte — an
// encoded slash in a repository name, say — must keep requesting that exact
// path. Everything else the configured remote carries, userinfo for a deployment
// that embeds credentials and a non-default port among it, still reaches the
// endpoint. A remote with no path has no repository to suffix, but the API root
// is still /info/lfs on that host.
func suffixedEndpoint(remoteURL *url.URL) string {
	endpoint := endpointBase(remoteURL)

	escaped := strings.TrimSuffix(remoteURL.EscapedPath(), "/")
	if escaped == "" {
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
// without adding the repository suffix.
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
