// Package paths derives storage object keys from repository URLs and names.
//
// Every forge-controlled value that reaches a storage key flows through
// NormalizeStorageSegment, so a hostile provider cannot inject extra key
// segments. The parser, the key builder, and the retention timestamp decode all
// live here so the key format has exactly one definition.
package paths

import (
	"net/url"
	"regexp"
	"strings"
)

// invalidStorageSegmentCharacters matches every character not allowed in a
// storage-key path segment or file name; each run is replaced with '-'.
var invalidStorageSegmentCharacters = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// NormalizeStorageSegment normalizes an untrusted value into a single safe
// storage-key segment: anything outside the safe charset becomes '-', then
// leading and trailing '-' and '.' are trimmed so values like "." or ".."
// collapse to fallback rather than surviving into a key as a path-traversal
// token. When lowercase is true the value is lowercased first so the same
// helper serves both case-sensitive file names and case-folded key segments.
func NormalizeStorageSegment(value, fallback string, lowercase bool) string {
	candidate := strings.TrimSpace(value)
	if lowercase {
		candidate = strings.ToLower(candidate)
	}

	sanitized := strings.Trim(invalidStorageSegmentCharacters.ReplaceAllString(candidate, "-"), "-.")
	if strings.TrimSpace(sanitized) == "" {
		return fallback
	}
	return sanitized
}

// TrimGitSuffix removes a trailing .git suffix (case-insensitive) from a
// repository URL or name, returning the value unchanged when none is present.
func TrimGitSuffix(value string) string {
	if len(value) >= 4 && strings.EqualFold(value[len(value)-4:], ".git") {
		return value[:len(value)-4]
	}
	return value
}

// RedactURL renders a URL with any embedded password masked, for safe inclusion
// in logs and error messages. A clone URL may carry userinfo such as
// https://user:token@host/owner/repo, and a token written to a log is a leaked
// credential. A value that does not parse is returned unchanged, because there
// is nothing to mask and dropping it would hide the failure being reported.
func RedactURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return rawURL
	}
	return parsed.Redacted()
}

// IsHTTPOrHTTPS reports whether the parsed URL uses the http or https scheme.
// It is the single predicate behind the transport allowlist, settings
// validation, and the storage-key parser.
func IsHTTPOrHTTPS(u *url.URL) bool {
	return strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
}

// ParseHTTPURL parses value as an absolute http/https URL, returning nil for
// anything else. Callers must not read the returned URL when ok is false.
func ParseHTTPURL(value string) (*url.URL, bool) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || !parsed.IsAbs() || !IsHTTPOrHTTPS(parsed) || parsed.Host == "" {
		return nil, false
	}
	return parsed, true
}

// SplitUnescapedSegments splits a URL's absolute path into its non-empty,
// URL-unescaped segments.
func SplitUnescapedSegments(u *url.URL) []string {
	escaped := u.EscapedPath()
	if escaped == "" {
		return nil
	}

	var segments []string
	for _, segment := range strings.Split(escaped, "/") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		unescaped, err := url.PathUnescape(segment)
		if err != nil {
			unescaped = segment
		}
		segments = append(segments, unescaped)
	}
	return segments
}
