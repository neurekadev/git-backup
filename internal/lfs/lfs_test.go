package lfs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func pointerFor(content []byte) (string, string) {
	sum := sha256.Sum256(content)
	oid := hex.EncodeToString(sum[:])
	pointerText := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", oid, len(content))
	return oid, pointerText
}

// newRepoWithLFS creates a working-copy repository committing the given files
// (name → content). LFS-pointer files should already be pointer text.
func newRepoWithLFS(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	repository, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := worktree.Add(name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := worktree.Commit("add files", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fakeLFSServer implements enough of the LFS batch protocol for the tests.
type fakeLFSServer struct {
	server     *httptest.Server
	mu         sync.Mutex
	data       map[string][]byte
	batchCalls int
	downloads  map[string]int
	// batchStatus, when non-zero, is the status returned for batch requests.
	batchStatus int
	// refusedOIDs are answered with a per-object error instead of a download
	// action, like a pointer whose object is gone from the server.
	refusedOIDs []string
	// rejectWhen, when set, decides the status of each batch request so a test
	// can model an endpoint that rejects some request shapes.
	rejectWhen func(batchRequest) int
	// corruptDownload serves wrong bytes for every object.
	corruptDownload bool
	// batchPath overrides the expected batch path (lfs.url override tests).
	batchPath string
}

func newFakeLFSServer(t *testing.T, data map[string][]byte) *fakeLFSServer {
	t.Helper()
	s := &fakeLFSServer{data: data, downloads: make(map[string]int)}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/objects/batch"):
			s.handleBatch(w, r)
		case strings.HasPrefix(r.URL.Path, "/download/"):
			s.handleDownload(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// remoteURL is the remote a repository would use to reach the fake server.
func (s *fakeLFSServer) remoteURL() string {
	return s.server.URL + "/repo.git"
}

func (s *fakeLFSServer) handleBatch(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.batchCalls++
	status, batchPath := s.batchStatus, s.batchPath
	rejectWhen := s.rejectWhen
	refused := make(map[string]struct{}, len(s.refusedOIDs))
	for _, oid := range s.refusedOIDs {
		refused[oid] = struct{}{}
	}
	s.mu.Unlock()

	if batchPath != "" && r.URL.Path != batchPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}

	var request batchRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Mimic a forge that rejects some batch requests, such as one carrying more
	// objects than its limit allows.
	if rejectWhen != nil {
		if code := rejectWhen(request); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
	}

	response := batchResponse{Objects: make([]batchResponseObject, 0, len(request.Objects))}
	for _, object := range request.Objects {
		if _, isRefused := refused[object.OID]; isRefused {
			response.Objects = append(response.Objects, batchResponseObject{
				OID:   object.OID,
				Error: &batchError{Code: http.StatusUnprocessableEntity, Message: "refused"},
			})
			continue
		}
		content, known := s.data[object.OID]
		if !known {
			response.Objects = append(response.Objects, batchResponseObject{
				OID:   object.OID,
				Error: &batchError{Code: http.StatusNotFound, Message: "Object does not exist"},
			})
			continue
		}
		response.Objects = append(response.Objects, batchResponseObject{
			OID:     object.OID,
			Size:    int64(len(content)),
			Actions: map[string]*batchAction{"download": {Href: s.server.URL + "/download/" + object.OID}},
		})
	}
	w.Header().Set("Content-Type", lfsMediaType)
	_ = json.NewEncoder(w).Encode(response)
}

func (s *fakeLFSServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	oid := strings.TrimPrefix(r.URL.Path, "/download/")
	s.mu.Lock()
	s.downloads[oid]++
	content, known := s.data[oid]
	corrupt := s.corruptDownload
	s.mu.Unlock()

	if !known {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if corrupt {
		content = []byte("corrupted!")
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(content)
}

func (s *fakeLFSServer) batchCallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.batchCalls
}

func (s *fakeLFSServer) downloadCount(oid string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.downloads[oid]
}

func TestParsePointer(t *testing.T) {
	content := []byte{1, 2, 3}
	oid, pointerText := pointerFor(content)

	parsed, ok := parsePointer([]byte(pointerText))
	if !ok {
		t.Fatal("valid pointer should parse")
	}
	if parsed.oid != oid || parsed.size != int64(len(content)) {
		t.Fatalf("parsed = %+v", parsed)
	}

	invalid := map[string]string{
		"missing version":  fmt.Sprintf("oid sha256:%s\nsize 3\n", strings.Repeat("a", 64)),
		"wrong version":    "version https://example.com/spec/v1\noid sha256:" + strings.Repeat("a", 64) + "\nsize 3\n",
		"missing oid":      "version https://git-lfs.github.com/spec/v1\nsize 3\n",
		"missing size":     "version https://git-lfs.github.com/spec/v1\noid sha256:" + strings.Repeat("a", 64) + "\n",
		"short oid":        "version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 3\n",
		"non-hex oid":      "version https://git-lfs.github.com/spec/v1\noid sha256:" + strings.Repeat("g", 64) + "\nsize 3\n",
		"negative size":    "version https://git-lfs.github.com/spec/v1\noid sha256:" + strings.Repeat("a", 64) + "\nsize -1\n",
		"not a key value":  "just some text\n",
		"binary gibberish": string([]byte{0, 1, 2, 3}),
	}
	for name, text := range invalid {
		if _, ok := parsePointer([]byte(text)); ok {
			t.Errorf("%s should not parse", name)
		}
	}

	// Unknown extension fields are allowed by the pointer spec.
	extended := pointerText + "x-anything custom-value\n"
	if _, ok := parsePointer([]byte(extended)); !ok {
		t.Error("pointer with extension fields should parse")
	}
}

func TestFetchAllDownloadsAndCaches(t *testing.T) {
	content := []byte("large model weights \x00\x01\x02")
	oid, pointerText := pointerFor(content)
	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: content})

	repositoryPath := newRepoWithLFS(t, map[string]string{
		"models/weights.bin": pointerText,
		"README.md":          "no LFS here",
	})

	fetcher := NewFetcher()
	if err := fetcher.FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "user", "pass"); err != nil {
		t.Fatalf("FetchAll failed: %v", err)
	}

	cached, err := os.ReadFile(filepath.Join(repositoryPath, ".git", "lfs", "objects", oid[0:2], oid[2:4], oid))
	if err != nil {
		t.Fatalf("LFS object not cached in the git-lfs layout: %v", err)
	}
	if string(cached) != string(content) {
		t.Error("cached content should match the served bytes")
	}
	if lfsServer.downloadCount(oid) != 1 {
		t.Errorf("download count = %d, want 1", lfsServer.downloadCount(oid))
	}

	// A repeated fetch must not re-download the cached object.
	if err := fetcher.FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "user", "pass"); err != nil {
		t.Fatalf("second FetchAll failed: %v", err)
	}
	if lfsServer.downloadCount(oid) != 1 {
		t.Errorf("cached object was downloaded again (count=%d)", lfsServer.downloadCount(oid))
	}
}

func TestFetchAllSkipsEndpointWhenNoPointers(t *testing.T) {
	lfsServer := newFakeLFSServer(t, nil)
	repositoryPath := newRepoWithLFS(t, map[string]string{"README.md": "plain repo"})

	if err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", ""); err != nil {
		t.Fatalf("FetchAll failed: %v", err)
	}
	if lfsServer.batchCallCount() != 0 {
		t.Errorf("batch endpoint should not be contacted without pointers (calls=%d)", lfsServer.batchCallCount())
	}
}

func TestFetchAllDisabledRemote(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
		lfsServer.batchStatus = status
		repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

		err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
		if !errors.Is(err, ErrDisabled) {
			t.Errorf("status %d should map to ErrDisabled, got %v", status, err)
		}
	}
}

func TestFetchAllUnauthorizedIsNotDisabled(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))
	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
	lfsServer.batchStatus = http.StatusUnauthorized
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || errors.Is(err, ErrDisabled) {
		t.Fatalf("401 should be a genuine error, got %v", err)
	}
}

func TestFetchAllHashMismatch(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))
	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
	lfsServer.corruptDownload = true
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("corrupt download should fail with a hash mismatch, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects", oid[0:2], oid[2:4], oid)); !os.IsNotExist(statErr) {
		t.Error("corrupted download must not be stored")
	}
}

func TestFetchAllHonorsLFSConfigOverride(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))
	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
	lfsServer.batchPath = "/custom/lfs/objects/batch"

	repositoryPath := newRepoWithLFS(t, map[string]string{
		".lfsconfig": "[lfs]\n\turl = " + lfsServer.server.URL + "/custom/lfs\n",
		"file.bin":   pointerText,
	})

	if err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", ""); err != nil {
		t.Fatalf("FetchAll with .lfsconfig override failed: %v", err)
	}
}

func TestFetchAllUnknownObjectFails(t *testing.T) {
	_, pointerText := pointerFor([]byte("content"))
	lfsServer := newFakeLFSServer(t, nil) // knows nothing
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || errors.Is(err, ErrDisabled) {
		t.Fatalf("unknown object should be a genuine error, got %v", err)
	}
	if !errors.Is(err, errObjectUnavailable) {
		t.Fatalf("err = %v, want it to report the object as unavailable", err)
	}
	if !strings.Contains(err.Error(), "could not be fetched") {
		t.Fatalf("err = %v, want it to say how many objects were skipped", err)
	}
}

// TestFetchAllFallsBackWhenBatchRejected covers forges that reject a batch
// request outright — an object limit, or a batch they refuse to process. The
// pointers must be retried one at a time so a single refused object cannot cost
// the repository's whole LFS mirror, while a refusal that hits every object is
// reported as the endpoint's failure.
func TestFetchAllFallsBackWhenBatchRejected(t *testing.T) {
	available := []byte("available content")
	availableOID, availablePointer := pointerFor(available)
	refused := []byte("refused content")
	refusedOID, refusedPointer := pointerFor(refused)
	result := func(oids ...string) string { return strings.Join(oids, ",") }

	cases := []struct {
		name        string
		request     func(batchRequest) int
		wantErr     string
		wantBatches int
		wantCached  string
	}{
		{
			name: "server object limit",
			request: func(request batchRequest) int {
				if len(request.Objects) > 1 {
					return http.StatusUnprocessableEntity
				}
				return http.StatusOK
			},
			wantBatches: 3,
			wantCached:  result(availableOID, refusedOID),
		},
		{
			name: "one object rejected, one refused",
			request: func(request batchRequest) int {
				for _, object := range request.Objects {
					if object.OID == refusedOID {
						return http.StatusUnprocessableEntity
					}
				}
				return http.StatusOK
			},
			wantErr:     "unavailable",
			wantBatches: 3,
			wantCached:  result(availableOID),
		},
		{
			name: "the endpoint refuses every batch",
			request: func(batchRequest) int {
				return http.StatusBadRequest
			},
			wantErr:     "rejected for 2 of 2 objects",
			wantBatches: 3,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lfsServer := newFakeLFSServer(t, map[string][]byte{
				availableOID: available,
				refusedOID:   refused,
			})
			lfsServer.rejectWhen = c.request
			repositoryPath := newRepoWithLFS(t, map[string]string{
				"big.bin":   availablePointer,
				"stale.bin": refusedPointer,
			})

			err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("FetchAll = %v, want success", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("FetchAll = %v, want an error containing %q", err, c.wantErr)
			}

			if calls := lfsServer.batchCallCount(); calls != c.wantBatches {
				t.Errorf("batch calls = %d, want %d", calls, c.wantBatches)
			}
			for _, oid := range strings.Split(c.wantCached, ",") {
				if oid == "" {
					continue
				}
				path := filepath.Join(repositoryPath, ".git", "lfs", "objects", oid[0:2], oid[2:4], oid)
				if _, err := os.Stat(path); err != nil {
					t.Errorf("object %s should be mirrored: %v", shortOID(oid), err)
				}
			}
		})
	}
}

func TestFetchAllChunksLargePointerSets(t *testing.T) {
	files := make(map[string]string, batchObjectLimit+2)
	data := make(map[string][]byte, batchObjectLimit+2)
	var lastOID string
	for index := range batchObjectLimit + 2 {
		content := []byte(fmt.Sprintf("object %d", index))
		oid, pointerText := pointerFor(content)
		data[oid] = content
		files[fmt.Sprintf("file-%03d.bin", index)] = pointerText
		lastOID = oid
	}

	lfsServer := newFakeLFSServer(t, data)
	repositoryPath := newRepoWithLFS(t, files)

	if err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", ""); err != nil {
		t.Fatalf("FetchAll failed: %v", err)
	}

	if calls := lfsServer.batchCallCount(); calls != 2 {
		t.Errorf("batch calls = %d, want one request per chunk of %d", calls, batchObjectLimit)
	}
	if _, err := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
		lastOID[0:2], lastOID[2:4], lastOID)); err != nil {
		t.Errorf("the last chunk should be mirrored too: %v", err)
	}
}

// TestCollectPointersHandlesWindowsIllegalNames covers a tree entry that cannot
// be materialised on the host — a backslash in a name is a path separator on
// Windows — and one that reuses a subtree hash, as a submodule-like entry does.
// Both must be walked without tripping the scan: the pointer beside them is
// still collected, and the shared tree is visited once.
func TestCollectPointersHandlesWindowsIllegalNames(t *testing.T) {
	dir := t.TempDir()
	repository, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}

	content := []byte("weights")
	oid, pointerText := pointerFor(content)
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nested", "weights.bin"), []byte(pointerText), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("nested/weights.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Commit("add pointer", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}

	head, err := repository.Head()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repository.CommitObject(head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	root, err := repository.TreeObject(commit.TreeHash)
	if err != nil {
		t.Fatal(err)
	}
	var nested object.TreeEntry
	for _, entry := range root.Entries {
		if entry.Name == "nested" {
			nested = entry
		}
	}
	if nested.Hash.IsZero() {
		t.Fatal("nested subtree not found")
	}

	hostile := &object.Tree{Entries: []object.TreeEntry{
		{Name: "nested-again", Hash: nested.Hash, Mode: filemode.Dir},
		{Name: "nested", Hash: nested.Hash, Mode: filemode.Dir},
		{Name: `src\windows.cpp`, Hash: plumbing.NewHash(strings.Repeat("a", 40)), Mode: filemode.Regular},
	}}
	encoded := repository.Storer.NewEncodedObject()
	if err := hostile.Encode(encoded); err != nil {
		t.Fatal(err)
	}
	hostileHash, err := repository.Storer.SetEncodedObject(encoded)
	if err != nil {
		t.Fatal(err)
	}

	headRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName("hostile"), hostileHash)
	if err := repository.Storer.SetReference(headRef); err != nil {
		t.Fatal(err)
	}

	pointers, err := collectPointers(context.Background(), repository)
	if err != nil {
		t.Fatalf("collectPointers failed on a tree with host-specific names: %v", err)
	}
	if len(pointers) != 1 || pointers[0].oid != oid {
		t.Fatalf("pointers = %+v, want the single pointer %s", pointers, oid)
	}
}

func TestFetchAllRejectsUnsafeLFSConfigOverrides(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))
	cases := []struct {
		name   string
		lfsURL string
	}{
		{"off-host override", "https://evil.example.com/lfs"},
		{"non-http scheme", "ssh://git@evil.example.com/repo.git/lfs"},
		{"relative value", "/custom/lfs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
			repositoryPath := newRepoWithLFS(t, map[string]string{
				".lfsconfig": "[lfs]\n\turl = " + c.lfsURL + "\n",
				"file.bin":   pointerText,
			})

			err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "user", "pass")
			if err == nil || !strings.Contains(err.Error(), "lfs.url") {
				t.Fatalf("err = %v, want it to name the lfs.url override", err)
			}
			if lfsServer.batchCallCount() != 0 {
				t.Error("the batch endpoint must not be contacted for an unsafe lfs.url override")
			}
		})
	}
}

func TestFetchAllRejectsNonHTTPRemoteURL(t *testing.T) {
	repositoryPath := newRepoWithLFS(t, map[string]string{"README.md": "plain repo"})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, "ftp://example.com/repo.git", "", "")
	if err == nil || !strings.Contains(err.Error(), "http and https") {
		t.Fatalf("err = %v, want an http/https rejection", err)
	}
}

func TestCanonicalHostStripsSchemeDefaultPorts(t *testing.T) {
	mustParse := func(raw string) *url.URL {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return parsed
	}

	if canonicalHost(mustParse("https://Example.com:443/lfs")) != canonicalHost(mustParse("https://example.com/lfs")) {
		t.Error("an explicit https default port must equal the implicit default")
	}
	if canonicalHost(mustParse("http://example.com:80/lfs")) != "example.com" {
		t.Errorf("http default port = %q, want example.com", canonicalHost(mustParse("http://example.com:80/lfs")))
	}
	if canonicalHost(mustParse("https://example.com:8443/lfs")) == canonicalHost(mustParse("https://example.com/lfs")) {
		t.Error("a non-default port must stay distinct from the bare host")
	}
}

// TestDefaultEndpointAddsGitSuffix pins the endpoint a forge expects: GitHub
// and GitLab answer a suffix-less /info/lfs with 422, so a configured remote
// without .git still has to request the suffixed path.
func TestDefaultEndpointAddsGitSuffix(t *testing.T) {
	cases := []struct {
		remoteURL string
		want      string
	}{
		{"https://github.com/owner/repo", "https://github.com/owner/repo.git/info/lfs"},
		{"https://github.com/owner/repo.git", "https://github.com/owner/repo.git/info/lfs"},
		{"https://github.com/owner/repo/", "https://github.com/owner/repo.git/info/lfs"},
		{"https://git.example.com:8443/group/sub/repo", "https://git.example.com:8443/group/sub/repo.git/info/lfs"},
	}

	for _, c := range cases {
		t.Run(c.remoteURL, func(t *testing.T) {
			parsed, err := url.Parse(c.remoteURL)
			if err != nil {
				t.Fatal(err)
			}
			if got := defaultEndpoint(parsed); got != c.want {
				t.Errorf("defaultEndpoint(%q) = %q, want %q", c.remoteURL, got, c.want)
			}
		})
	}
}

func TestResolveEndpointOverrideHostAndScheme(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))
	cases := []struct {
		name        string
		lfsURL      string
		remoteURL   string
		wantReject  bool
		wantAddress string
	}{
		{
			name:        "explicit default port matches bare remote host",
			lfsURL:      "https://example.com:443/custom/lfs",
			remoteURL:   "https://example.com/repo.git",
			wantAddress: "https://example.com/custom/lfs",
		},
		{
			name:       "http override downgrades the https remote",
			lfsURL:     "http://example.com/custom/lfs",
			remoteURL:  "https://example.com/repo.git",
			wantReject: true,
		},
		{
			name:       "foreign port on the remote host",
			lfsURL:     "https://example.com:8443/custom/lfs",
			remoteURL:  "https://example.com/repo.git",
			wantReject: true,
		},
		{
			name:       "off-host override",
			lfsURL:     "https://evil.example.com/lfs",
			remoteURL:  "https://example.com/repo.git",
			wantReject: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
			repositoryPath := newRepoWithLFS(t, map[string]string{
				".lfsconfig": "[lfs]\n\turl = " + c.lfsURL + "\n",
				"file.bin":   pointerText,
			})
			repository, err := git.PlainOpen(repositoryPath)
			if err != nil {
				t.Fatal(err)
			}

			address, err := resolveEndpoint(repository, c.remoteURL)
			if c.wantReject {
				if err == nil {
					t.Fatalf("resolveEndpoint = %q, want rejection", address)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEndpoint failed: %v", err)
			}
			if address != c.wantAddress {
				t.Errorf("endpoint = %q, want %q", address, c.wantAddress)
			}
			if lfsServer.batchCallCount() != 0 {
				t.Error("resolveEndpoint must not contact any endpoint")
			}
		})
	}
}
