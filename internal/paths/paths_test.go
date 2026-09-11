package paths

import (
	"strings"
	"testing"
)

func TestNormalizeStorageSegment(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		fallback  string
		lowercase bool
		want      string
	}{
		{name: "plain value", value: "My-Repo.Name_1", fallback: "unknown", want: "My-Repo.Name_1"},
		{name: "lowercased", value: "My-Repo", fallback: "unknown", lowercase: true, want: "my-repo"},
		{name: "hostile traversal", value: "../../etc/passwd", fallback: "unknown", want: "etc-passwd"},
		{name: "slash becomes separator", value: "a/b c", fallback: "unknown", want: "a-b-c"},
		{name: "trimmed separators", value: "..--foo--..", fallback: "unknown", want: "foo"},
		{name: "dot collapses to fallback", value: ".", fallback: "unknown", want: "unknown"},
		{name: "dotdot collapses to fallback", value: "..", fallback: "unknown", want: "unknown"},
		{name: "blank falls back", value: "   ", fallback: "unknown", want: "unknown"},
		{name: "padded", value: " padded ", fallback: "unknown", want: "padded"},
		{name: "unicode replaced", value: "répo", fallback: "unknown", want: "r-po"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeStorageSegment(tt.value, tt.fallback, tt.lowercase); got != tt.want {
				t.Fatalf("NormalizeStorageSegment(%q, %q, %v) = %q, want %q", tt.value, tt.fallback, tt.lowercase, got, tt.want)
			}
		})
	}
}

func TestTrimGitSuffix(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "repo.git", want: "repo"},
		{value: "REPO.GIT", want: "REPO"},
		{value: "repo.gitx", want: "repo.gitx"},
		{value: "repo", want: "repo"},
		{value: ".git", want: ""},
	}
	for _, tt := range tests {
		if got := TrimGitSuffix(tt.value); got != tt.want {
			t.Errorf("TrimGitSuffix(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "masks a password", raw: "https://user:token@host/owner/repo", want: "https://user:xxxxx@host/owner/repo"},
		{name: "masks only the password", raw: "https://user:tok@host:8443/owner/repo.git", want: "https://user:xxxxx@host:8443/owner/repo.git"},
		{name: "keeps a username", raw: "https://user@host/owner/repo", want: "https://user@host/owner/repo"},
		{name: "leaves a url without userinfo alone", raw: "https://host/owner/repo", want: "https://host/owner/repo"},
		{name: "masks a password in a value the parser rejects", raw: "https://user:token@exa mple.com/repo", want: "https://user:xxxxx@exa mple.com/repo"},
		{name: "masks a password before a bad port", raw: "https://user:token@host:notaport/repo", want: "https://user:xxxxx@host:notaport/repo"},
		{name: "masks a password with a space in it", raw: "https://user:p@ss word@host/repo", want: "https://user:xxxxx@host/repo"},
		{name: "masks a password under another scheme", raw: "ssh://user:token@host:22/repo", want: "ssh://user:xxxxx@host:22/repo"},
		{name: "masks a password containing a slash", raw: "https://user:tok/en@host/repo", want: "https://user:xxxxx@host/repo"},
		{name: "masks a password containing a question mark", raw: "https://user:tok?en@host/repo", want: "https://user:xxxxx@host/repo"},
		{name: "masks a password containing a hash", raw: "https://user:tok#en@host/repo", want: "https://user:xxxxx@host/repo"},
		{name: "leaves a host and port without userinfo alone", raw: "https://host:8080/repo", want: "https://host:8080/repo"},
		{name: "leaves an unparseable value without userinfo alone", raw: "http://[::1", want: "http://[::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactURL(tt.raw); got != tt.want {
				t.Errorf("RedactURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseHTTPURL(t *testing.T) {
	ok := []string{"https://example.com/x", "http://10.0.0.1:9000", "HTTPS://EXAMPLE.COM", " https://padded.example.com "}
	for _, value := range ok {
		if _, valid := ParseHTTPURL(value); !valid {
			t.Errorf("ParseHTTPURL(%q) should accept", value)
		}
	}

	rejected := []string{"", "not a url", "ftp://example.com", "file:///tmp", "//example.com/x", "https://", "ext::sh -c cat"}
	for _, value := range rejected {
		if _, valid := ParseHTTPURL(value); valid {
			t.Errorf("ParseHTTPURL(%q) should reject", value)
		}
	}
}

func TestParseRepositoryPath(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want PathInfo
	}{
		{
			name: "owner and repo",
			url:  "https://github.com/octocat/hello.git",
			want: PathInfo{FullDomain: "github.com", Owner: "octocat", RepositoryName: "hello"},
		},
		{
			name: "owner group repo",
			url:  "https://gitlab.com/group/project.git",
			want: PathInfo{FullDomain: "gitlab.com", Owner: "group", RepositoryName: "project"},
		},
		{
			name: "deep hierarchy joins middle segments",
			url:  "https://gitlab.com/group/sub/inner/project.git",
			want: PathInfo{FullDomain: "gitlab.com", Owner: "group", Group: "sub", SecondaryGroup: "inner", RepositoryName: "project"},
		},
		{
			name: "very deep hierarchy",
			url:  "https://gitlab.com/a/b/c/d/e",
			want: PathInfo{FullDomain: "gitlab.com", Owner: "a", Group: "b", SecondaryGroup: "c-d", RepositoryName: "e"},
		},
		{
			name: "port and case are normalized",
			url:  "http://Forge.Example.COM:8443/Owner/Repo",
			want: PathInfo{FullDomain: "forge.example.com", Owner: "owner", RepositoryName: "repo"},
		},
		{
			name: "escaped segments are unescaped then normalized",
			url:  "https://example.com/O%20wner/re.po.git",
			want: PathInfo{FullDomain: "example.com", Owner: "o-wner", RepositoryName: "re.po"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRepositoryPath(tt.url)
			if err != nil {
				t.Fatalf("ParseRepositoryPath(%q) returned error: %v", tt.url, err)
			}
			if got != tt.want {
				t.Fatalf("ParseRepositoryPath(%q) = %+v, want %+v", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseRepositoryPathErrors(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "relative", url: "owner/repo"},
		{name: "no scheme", url: "example.com/owner/repo"},
		{name: "unsupported scheme", url: "ssh://git@example.com/owner/repo.git"},
		{name: "missing repository segment", url: "https://example.com/owner"},
		{name: "no segments", url: "https://example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRepositoryPath(tt.url)
			if err == nil {
				t.Fatalf("ParseRepositoryPath(%q) should fail", tt.url)
			}
			if !strings.Contains(err.Error(), tt.url) {
				t.Errorf("error %q should reference the URL", err)
			}
		})
	}
}

func TestHierarchyOmitsEmptyGroups(t *testing.T) {
	info := PathInfo{FullDomain: "example.com", Owner: "octo", RepositoryName: "repo"}
	got := strings.Join(info.Hierarchy(), "|")
	if got != "octo|repo" {
		t.Fatalf("Hierarchy = %q, want %q", got, "octo|repo")
	}
}

func TestBuildProviderRepositoryPrefix(t *testing.T) {
	info, err := ParseRepositoryPath("https://gitlab.com/group/sub/project.git")
	if err != nil {
		t.Fatal(err)
	}
	want := "repositories/provider/gitlab/group/sub/project"
	if got := BuildProviderRepositoryPrefix(" GitLab ", info); got != want {
		t.Fatalf("BuildProviderRepositoryPrefix = %q, want %q", got, want)
	}
}

func TestBuildSnippetResourcePrefix(t *testing.T) {
	tests := []struct {
		name       string
		provider   string
		identifier string
		want       string
	}{
		{name: "plain id", provider: "github", identifier: "abc123", want: "snippets/provider/github/abc123"},
		{name: "hostile id sanitized", provider: "github", identifier: "../secret", want: "snippets/provider/github/secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildSnippetResourcePrefix(tt.provider, tt.identifier); got != tt.want {
				t.Fatalf("BuildSnippetResourcePrefix = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildURLRepositoryPrefix(t *testing.T) {
	info, err := ParseRepositoryPath("https://example.com/owner/repo.git")
	if err != nil {
		t.Fatal(err)
	}
	want := "repositories/url/example.com/owner/repo"
	if got := BuildURLRepositoryPrefix(info); got != want {
		t.Fatalf("BuildURLRepositoryPrefix = %q, want %q", got, want)
	}
}

func TestArchiveKeys(t *testing.T) {
	key := BuildArchiveObjectKey("repositories/provider/github/octo/repo", 1700000000)
	if want := "repositories/provider/github/octo/repo/1700000000_repo.tar.gz"; key != want {
		t.Fatalf("BuildArchiveObjectKey = %q, want %q", key, want)
	}
	got, ok := TryGetArchiveTimestamp(key)
	if !ok || got != 1700000000 {
		t.Fatalf("TryGetArchiveTimestamp(%q) = %d, %v", key, got, ok)
	}

	if _, ok := TryGetArchiveTimestamp(key + "x"); ok {
		t.Error("non-archive suffix should not parse")
	}
	if _, ok := TryGetArchiveTimestamp("repositories/provider/github/octo/repo/metadata.json"); ok {
		t.Error("metadata key should not parse")
	}
	if _, ok := TryGetArchiveTimestamp("repositories/provider/github/octo/repo/0_repo.tar.gz"); ok {
		t.Error("zero timestamp should not parse")
	}
	if _, ok := TryGetArchiveTimestamp("repositories/provider/github/octo/repo/abc_repo.tar.gz"); ok {
		t.Error("non-numeric timestamp should not parse")
	}
}

func TestBuildCollectionKeys(t *testing.T) {
	prefix := "repositories/provider/github/octo/repo"
	if got, want := BuildIssueObjectKey(prefix, "12"), prefix+"/issues/12.json"; got != want {
		t.Errorf("BuildIssueObjectKey = %q, want %q", got, want)
	}
	if got, want := BuildMergeRequestObjectKey(prefix, "7"), prefix+"/merge-requests/7.json"; got != want {
		t.Errorf("BuildMergeRequestObjectKey = %q, want %q", got, want)
	}
	if got, want := BuildReleaseObjectKey(prefix, "v1.0"), prefix+"/releases/v1.0.json"; got != want {
		t.Errorf("BuildReleaseObjectKey = %q, want %q", got, want)
	}
	if got, want := BuildReleasesManifestObjectKey(prefix), prefix+"/releases/index.json"; got != want {
		t.Errorf("BuildReleasesManifestObjectKey = %q, want %q", got, want)
	}
	if got, want := BuildIssueAttachmentObjectKey(prefix, "12", "img.png"), prefix+"/issues/attachments/12/img.png"; got != want {
		t.Errorf("BuildIssueAttachmentObjectKey = %q, want %q", got, want)
	}
}

func TestBuildNestedSnippetPrefix(t *testing.T) {
	if got, want := BuildNestedSnippetPrefix("repositories/provider/gitlab/group/project", "42"), "repositories/provider/gitlab/group/project/snippets/42"; got != want {
		t.Fatalf("BuildNestedSnippetPrefix = %q, want %q", got, want)
	}
	if got := BuildNestedSnippetPrefix("/p/", ".."); got != "p/snippets/unknown" {
		t.Fatalf("hostile identifier should collapse to fallback, got %q", got)
	}
}

func TestGetParentPrefix(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{key: "a/b/c.json", want: "a/b"},
		{key: "a/metadata.json", want: "a"},
		{key: "top.json", want: ""},
		{key: "", want: ""},
	}
	for _, tt := range tests {
		if got := GetParentPrefix(tt.key); got != tt.want {
			t.Errorf("GetParentPrefix(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

func TestEnsurePrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "repositories/provider/github/octo/repo", want: "repositories/provider/github/octo/repo/"},
		{input: "repositories/provider/github/octo/repo/", want: "repositories/provider/github/octo/repo/"},
		{input: "/wrapped/", want: "wrapped/"},
		{input: "", want: ""},
		{input: "///", want: ""},
	}
	for _, tt := range tests {
		if got := EnsurePrefix(tt.input); got != tt.want {
			t.Errorf("EnsurePrefix(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
