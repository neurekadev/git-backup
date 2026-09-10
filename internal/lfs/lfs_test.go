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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	// actionlessOIDs are answered with neither an error nor a download action,
	// as a misbehaving endpoint may do.
	actionlessOIDs []string
	// rejectWhen, when set, decides the status of each batch request so a test
	// can model an endpoint that rejects some request shapes.
	rejectWhen func(batchRequest) int
	// corruptDownload serves wrong bytes for every object.
	corruptDownload bool
	// batchPath overrides the expected batch path (lfs.url override tests).
	batchPath string
	// servePaths, when set, are the only batch paths the server answers, so any
	// other path answers 404 like a host with no LFS service mounted there.
	servePaths []string
	// disabledPaths answer 403, the response for a repository with LFS switched
	// off, which is not the same as a path with no service behind it.
	disabledPaths []string
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

// plainRemoteURL is the same repository addressed without its .git suffix, the
// form a configuration normally carries.
func (s *fakeLFSServer) plainRemoteURL() string {
	return s.server.URL + "/repo"
}

// endpointFor mounts the server's batch API at the path a remote addresses, so
// a test chooses where the LFS service answers, and makes every other path
// answer 404 like a host with nothing mounted there.
func (s *fakeLFSServer) endpointFor(remoteURL string) string {
	s.serve([]string{remoteURL})
	return remoteURL
}

// disabledFor makes the given remotes answer 403 — the response a forge uses for
// a repository with LFS switched off — while the rest answer 404.
func (s *fakeLFSServer) disabledFor(remoteURLs ...string) {
	disabled := make([]string, 0, len(remoteURLs))
	for _, remoteURL := range remoteURLs {
		disabled = append(disabled, batchPathFor(remoteURL))
	}
	s.mu.Lock()
	s.disabledPaths = disabled
	s.mu.Unlock()
}

// serve mounts the batch API at the paths the given remotes address.
func (s *fakeLFSServer) serve(remoteURLs []string) {
	served := make([]string, 0, len(remoteURLs))
	for _, remoteURL := range remoteURLs {
		served = append(served, batchPathFor(remoteURL))
	}
	s.mu.Lock()
	s.servePaths = served
	s.mu.Unlock()
}

// batchPathFor is the batch action path a remote addresses.
func batchPathFor(remoteURL string) string {
	parsed, err := url.Parse(remoteURL)
	if err != nil {
		return remoteURL
	}
	return parsed.Path + "/info/lfs/objects/batch"
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
	actionless := make(map[string]struct{}, len(s.actionlessOIDs))
	for _, oid := range s.actionlessOIDs {
		actionless[oid] = struct{}{}
	}
	disabled := slices.Contains(s.disabledPaths, r.URL.Path)
	servedHere := slices.Contains(s.servePaths, r.URL.Path)
	hasServePaths := len(s.servePaths) > 0
	s.mu.Unlock()

	// A path the server does not serve answers 404, the response that tells a
	// client no LFS service is mounted there.
	if batchPath != "" && r.URL.Path != batchPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if hasServePaths && !servedHere {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if disabled {
		// A forge with LFS switched off explains itself in JSON; a host with no
		// service behind the path answers with its own HTML page.
		w.Header().Set("Content-Type", lfsMediaType)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"Git LFS is disabled for this repository."}`))
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
		if _, bare := actionless[object.OID]; bare {
			// The server knows the object but schedules nothing for it: a
			// successful response the client cannot act on.
			response.Objects = append(response.Objects, batchResponseObject{
				OID:  object.OID,
				Size: int64(len(content)),
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
	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
	// Both candidate paths answer as a repository with LFS switched off.
	lfsServer.disabledFor(lfsServer.plainRemoteURL(), lfsServer.remoteURL())
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.plainRemoteURL(), "", "")
	if !errors.Is(err, ErrDisabled) {
		t.Errorf("a 403 from every candidate should map to ErrDisabled, got %v", err)
	}
}

// TestFetchAllFallsBackToTheConfiguredPath covers a host that mounts its LFS
// service exactly where the remote points rather than under the repository's
// .git path: the suffixed endpoint answers 404, and the suffix-less one must
// then be tried rather than the remote being written off as LFS-free.
func TestFetchAllFallsBackToTheConfiguredPath(t *testing.T) {
	content := []byte("content")
	oid, pointerText := pointerFor(content)

	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: content})
	remoteURL := lfsServer.endpointFor(lfsServer.plainRemoteURL())
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	if err := NewFetcher().FetchAll(context.Background(), repositoryPath, remoteURL, "", ""); err != nil {
		t.Fatalf("FetchAll failed: %v", err)
	}
	cached, err := os.ReadFile(filepath.Join(repositoryPath, ".git", "lfs", "objects",
		oid[0:2], oid[2:4], oid))
	if err != nil {
		t.Fatalf("the object should be mirrored through the fallback endpoint: %v", err)
	}
	if string(cached) != string(content) {
		t.Error("mirrored content should match the served bytes")
	}
}

// TestFetchAllFallsBackWhenTheGuessIsForbidden covers the guessed .git path
// answering 403 while the configured path serves normally. The 403 is about a
// path that does not exist rather than about the repository's LFS setting, so it
// must not be believed before the other candidate has been tried.
func TestFetchAllFallsBackWhenTheGuessIsForbidden(t *testing.T) {
	content := []byte("content")
	oid, pointerText := pointerFor(content)

	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: content})
	remoteURL := lfsServer.endpointFor(lfsServer.plainRemoteURL())
	lfsServer.disabledFor(lfsServer.remoteURL())
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	if err := NewFetcher().FetchAll(context.Background(), repositoryPath, remoteURL, "", ""); err != nil {
		t.Fatalf("FetchAll failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
		oid[0:2], oid[2:4], oid)); err != nil {
		t.Errorf("the configured path should still be tried after a 403 on the guess: %v", err)
	}
}

// TestFetchAllNoEndpointAnywhereIsReported covers a host with no LFS service at
// either candidate path, which the mirror layer records as LFS being switched
// off — the two are indistinguishable from here, and both are expected states
// rather than a failed repository.
func TestFetchAllNoEndpointAnywhereIsReported(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))

	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
	lfsServer.endpointFor(lfsServer.server.URL + "/somewhere/else")
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.plainRemoteURL(), "", "")
	if errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("err = %v, want the expected-skip verdict rather than an internal signal", err)
	}
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
}

// TestFetchAllNotServedAnywhereIsSkipped covers a host whose every candidate
// path answers 404, which is both how a repository with LFS switched off looks
// on a forge that does not distinguish the two and how a host with no LFS
// service at all looks. Either way the mirror layer's expected skip is the right
// outcome, not a repository-wide failure.
func TestFetchAllNotServedAnywhereIsSkipped(t *testing.T) {
	oid, pointerText := pointerFor([]byte("content"))

	lfsServer := newFakeLFSServer(t, map[string][]byte{oid: []byte("content")})
	lfsServer.endpointFor(lfsServer.server.URL + "/somewhere/else")
	repositoryPath := newRepoWithLFS(t, map[string]string{"file.bin": pointerText})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.plainRemoteURL(), "", "")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled when no candidate serves the API", err)
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
// request outright — an object limit, or a request they refuse to process. The
// pointers must be narrowed down so a single refused object cannot cost the
// repository's whole LFS mirror, while a refusal that hits every object is
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
			// The chunk splits into two singletons, both are served, and the
			// candidate succeeds — so there is nothing left to probe.
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
			// The chunk splits once and the refused half's lone pointer is
			// rejected on its own request; the remote already carries the
			// suffix, so there is no second candidate path to probe.
			wantErr:     "unavailable",
			wantBatches: 3,
			wantCached:  result(availableOID),
		},
		{
			name: "the endpoint refuses every batch",
			request: func(batchRequest) int {
				return http.StatusBadRequest
			},
			// Splitting, not per-object fan-out: both halves narrow to the
			// rejection before it is reported as the endpoint's.
			wantErr:     "rejected",
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

// TestFetchAllSkipsObjectsWithoutDownloadAction covers a successful batch
// response that schedules no action for one object: the object the client
// cannot act on must be reported, and the objects scheduled beside it must
// still reach the mirror (internal/lfs/batch.go turns the missing action into
// the unavailable sentinel that downloadChunk has to isolate).
func TestFetchAllSkipsObjectsWithoutDownloadAction(t *testing.T) {
	first := []byte("first content")
	firstOID, firstPointer := pointerFor(first)
	second := []byte("second content")
	secondOID, secondPointer := pointerFor(second)
	third := []byte("third content")
	thirdOID, thirdPointer := pointerFor(third)

	lfsServer := newFakeLFSServer(t, map[string][]byte{
		firstOID:  first,
		secondOID: second,
		thirdOID:  third,
	})
	lfsServer.actionlessOIDs = []string{secondOID}
	repositoryPath := newRepoWithLFS(t, map[string]string{
		"first.bin":  firstPointer,
		"second.bin": secondPointer,
		"third.bin":  thirdPointer,
	})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil {
		t.Fatal("an object without a download action should be reported")
	}
	if !strings.Contains(err.Error(), "could not be fetched") {
		t.Fatalf("err = %v, want it to say how many objects were skipped", err)
	}
	if !errors.Is(err, errObjectUnavailable) {
		t.Fatalf("err = %v, want it to report the object as unavailable", err)
	}

	for _, oid := range []string{firstOID, thirdOID} {
		path := filepath.Join(repositoryPath, ".git", "lfs", "objects", oid[0:2], oid[2:4], oid)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("object %s should be mirrored beside the actionless one: %v", shortOID(oid), err)
		}
	}
	if path := filepath.Join(repositoryPath, ".git", "lfs", "objects", secondOID[0:2], secondOID[2:4], secondOID); func() bool {
		_, err := os.Stat(path)
		return err == nil
	}() {
		t.Error("the actionless object must not be stored")
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

// TestFetchAllStopsAfterRepeatedEndpointFailure covers an endpoint whose
// failures are not about the request's shape — dropped connections, and the
// credentials and server statuses that mean the same thing. Splitting the chunk
// would only repeat the answer, so the fetch must fail fast rather than narrow,
// while still attempting one more chunk before concluding the endpoint is down.
func TestFetchAllStopsAfterRepeatedEndpointFailure(t *testing.T) {
	files := make(map[string]string, batchObjectLimit*5)
	for index := range batchObjectLimit * 5 {
		_, pointerText := pointerFor([]byte(fmt.Sprintf("object %d", index)))
		files[fmt.Sprintf("file-%04d.bin", index)] = pointerText
	}
	repositoryPath := newRepoWithLFS(t, files)

	t.Run("dropped connections", func(t *testing.T) {
		var requests int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt64(&requests, 1)
			hijacked, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_ = hijacked.Close()
		}))
		t.Cleanup(server.Close)

		err := NewFetcher().FetchAll(context.Background(), repositoryPath, server.URL+"/repo.git", "", "")
		if err == nil {
			t.Fatal("an endpoint that never answers should be reported")
		}
		if errors.Is(err, errObjectUnavailable) {
			t.Errorf("err = %v, want a transport failure rather than per-object unavailability", err)
		}
		if got := atomic.LoadInt64(&requests); got != 2 {
			t.Errorf("batch requests = %d, want one attempt per tried chunk and no splitting", got)
		}
	})

	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			lfsServer := newFakeLFSServer(t, nil)
			lfsServer.batchStatus = status

			err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("FetchAll = %v, want the endpoint's status", err)
			}
			if errors.Is(err, errObjectUnavailable) {
				t.Errorf("err = %v, want the endpoint failure rather than per-object unavailability", err)
			}
			// No halving: one attempt for the first chunk, one for the second.
			if calls := lfsServer.batchCallCount(); calls != 2 {
				t.Errorf("batch calls = %d, want no splitting for a status about the endpoint", calls)
			}
		})
	}
}

// TestFetchAllReportsSystematicRejection covers an endpoint that rejects every
// request as unprocessable, including single-object ones, so the rejection
// outlives every split. It must be reported as the endpoint's — not attributed
// to each object as unavailable — and the sweep must stop once a second chunk
// confirms it rather than narrowing its way through the whole repository.
func TestFetchAllReportsSystematicRejection(t *testing.T) {
	const pointers = batchObjectLimit * 5
	files := make(map[string]string, pointers)
	for index := range pointers {
		_, pointerText := pointerFor([]byte(fmt.Sprintf("object %d", index)))
		files[fmt.Sprintf("file-%04d.bin", index)] = pointerText
	}

	lfsServer := newFakeLFSServer(t, nil)
	lfsServer.batchStatus = http.StatusUnprocessableEntity
	repositoryPath := newRepoWithLFS(t, files)

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("FetchAll = %v, want the endpoint rejection reported", err)
	}
	if errors.Is(err, errObjectUnavailable) {
		t.Errorf("err = %v, want an endpoint rejection rather than per-object unavailability", err)
	}
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("err = %v, want the endpoint's status", err)
	}

	// Two chunks are narrowed — the first to establish the rejection and the
	// second to confirm it is the endpoint's — and the rest are left alone. A
	// per-pointer sweep of this repository would take five hundred requests; the
	// remote carries its suffix, so only one candidate path is tried.
	if calls := lfsServer.batchCallCount(); calls > 450 {
		t.Errorf("batch calls = %d, want the systematic rejection to stop the sweep", calls)
	}
}

// TestFetchAllNarrowsBothHalves covers a rejection that narrows onto a broken
// half: the sibling half must still be requested and downloaded, rather than
// being abandoned because the first half reported the endpoint's rejection.
func TestFetchAllNarrowsBothHalves(t *testing.T) {
	bad := []byte("bad content")
	badOID, badPointer := pointerFor(bad)
	good := []byte("good content")
	goodOID, goodPointer := pointerFor(good)

	lfsServer := newFakeLFSServer(t, map[string][]byte{
		badOID:  bad,
		goodOID: good,
	})
	// Every request naming the bad object is refused, so the chunk narrows down
	// its first half while the second half is served normally.
	lfsServer.rejectWhen = func(request batchRequest) int {
		for _, object := range request.Objects {
			if object.OID == badOID {
				return http.StatusUnprocessableEntity
			}
		}
		return http.StatusOK
	}
	repositoryPath := newRepoWithLFS(t, map[string]string{
		"bad.bin":  badPointer,
		"good.bin": goodPointer,
	})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("FetchAll = %v, want the refused object reported", err)
	}
	if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
		goodOID[0:2], goodOID[2:4], goodOID)); statErr != nil {
		t.Errorf("the sibling half should be downloaded: %v", statErr)
	}
}

// TestFetchAllKeepsObjectsBesideAnAnsweredRejection covers a chunk whose halves
// disagree: one half's batch is refused down to a single object, while the other
// half's batch is answered with an object the endpoint will not serve. The
// answer proves the endpoint processes batches, so the refused object must not be
// mistaken for a broken endpoint — which would end the fetch and leave the
// answered half's siblings unattempted.
func TestFetchAllKeepsObjectsBesideAnAnsweredRejection(t *testing.T) {
	held := []byte("held content")
	heldOID, heldPointer := pointerFor(held)
	phantom := []byte("phantom content")
	phantomOID, phantomPointer := pointerFor(phantom)
	refused := []byte("refused content")
	refusedOID, refusedPointer := pointerFor(refused)

	lfsServer := newFakeLFSServer(t, map[string][]byte{
		heldOID:    held,
		phantomOID: phantom,
		refusedOID: refused,
	})
	lfsServer.refusedOIDs = []string{phantomOID}
	lfsServer.rejectWhen = func(request batchRequest) int {
		for _, object := range request.Objects {
			if object.OID == refusedOID {
				return http.StatusUnprocessableEntity
			}
		}
		return http.StatusOK
	}
	repositoryPath := newRepoWithLFS(t, map[string]string{
		"held.bin":    heldPointer,
		"phantom.bin": phantomPointer,
		"refused.bin": refusedPointer,
	})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("FetchAll = %v, want the two unfetchable objects reported", err)
	}

	for _, oid := range []string{heldOID} {
		if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
			oid[0:2], oid[2:4], oid)); statErr != nil {
			t.Errorf("object %s should be mirrored: %v", shortOID(oid), statErr)
		}
	}
}

// TestFetchAllKeepsSweepingAfterARefusedChunk covers a chunk the endpoint
// answers nothing for — every object refused, which alone looks like an endpoint
// rejecting every request — followed by a chunk it serves. The refused chunk
// must not end the sweep, or a chunk of stale pointers would cost the repository
// everything after it.
func TestFetchAllKeepsSweepingAfterARefusedChunk(t *testing.T) {
	const staleInFirstChunk = 3
	files := make(map[string]string, batchObjectLimit*2)
	data := make(map[string][]byte, batchObjectLimit*2)
	var staleOIDs []string
	for index := range batchObjectLimit * 2 {
		content := []byte(fmt.Sprintf("object %d", index))
		oid, pointerText := pointerFor(content)
		data[oid] = content
		files[fmt.Sprintf("file-%04d.bin", index)] = pointerText
		if index < staleInFirstChunk {
			staleOIDs = append(staleOIDs, oid)
		}
	}

	lfsServer := newFakeLFSServer(t, data)
	lfsServer.rejectWhen = func(request batchRequest) int {
		for _, object := range request.Objects {
			for _, stale := range staleOIDs {
				if object.OID == stale {
					return http.StatusUnprocessableEntity
				}
			}
		}
		return http.StatusOK
	}
	repositoryPath := newRepoWithLFS(t, files)

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || !strings.Contains(err.Error(), "could not be fetched") {
		t.Fatalf("FetchAll = %v, want the refused objects summarised", err)
	}

	// The chunk after the refused one is still fetched.
	last := fmt.Sprintf("object %d", batchObjectLimit*2-1)
	lastOID, _ := pointerFor([]byte(last))
	if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
		lastOID[0:2], lastOID[2:4], lastOID)); statErr != nil {
		t.Errorf("the chunk after a refused one should still be fetched: %v", statErr)
	}
	for _, oid := range staleOIDs {
		if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
			oid[0:2], oid[2:4], oid)); statErr == nil {
			t.Errorf("refused object %s must not be stored", shortOID(oid))
		}
	}
}

// TestFetchAllKeepsObjectsBesideARefusedHalf covers a chunk whose first half is
// refused in full while its sibling is servable: the first half answers nothing
// at all, which looks like an endpoint-wide rejection, and concluding that from
// one half alone would abandon the sibling — and, one chunk later, the rest of
// the repository.
func TestFetchAllKeepsObjectsBesideARefusedHalf(t *testing.T) {
	staleA := []byte("stale a")
	staleAOID, staleAPointer := pointerFor(staleA)
	staleB := []byte("stale b")
	staleBOID, staleBPointer := pointerFor(staleB)
	goodC := []byte("good c")
	goodCOID, goodCPointer := pointerFor(goodC)

	lfsServer := newFakeLFSServer(t, map[string][]byte{
		staleAOID: staleA,
		staleBOID: staleB,
		goodCOID:  goodC,
	})
	// Requests naming either stale object are refused, so a half holding both
	// narrows to rejections that the endpoint never answers.
	lfsServer.rejectWhen = func(request batchRequest) int {
		for _, object := range request.Objects {
			if object.OID == staleAOID || object.OID == staleBOID {
				return http.StatusUnprocessableEntity
			}
		}
		return http.StatusOK
	}
	repositoryPath := newRepoWithLFS(t, map[string]string{
		"stale-a.bin": staleAPointer,
		"stale-b.bin": staleBPointer,
		"good-c.bin":  goodCPointer,
	})

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("FetchAll = %v, want the refused objects reported", err)
	}
	if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
		goodCOID[0:2], goodCOID[2:4], goodCOID)); statErr != nil {
		t.Errorf("the servable sibling half should still be fetched: %v", statErr)
	}
}

// TestCollectPointersHandlesWindowsIllegalNames covers a tree entry that cannot
// be materialised on the host — a backslash in a name is a path separator on
// Windows — and one that reuses a subtree hash, as a submodule-like entry does.
// Both must be walked without tripping the scan: the pointer beside them is
// still collected, and the shared tree is visited once.
// TestFetchAllReportsAnEndpointThatStopsPartway covers a service that serves
// the first chunk and then answers as if it were not there any more. Part of the
// repository is mirrored by then, so the "no LFS here" verdict must not be
// recorded as a clean skip: that would report a half-finished mirror as
// complete.
func TestFetchAllReportsAnEndpointThatStopsPartway(t *testing.T) {
	const pointers = batchObjectLimit * 2
	files := make(map[string]string, pointers)
	data := make(map[string][]byte, pointers)
	for index := range pointers {
		content := []byte(fmt.Sprintf("object %d", index))
		oid, pointerText := pointerFor(content)
		data[oid] = content
		files[fmt.Sprintf("file-%04d.bin", index)] = pointerText
	}

	lfsServer := newFakeLFSServer(t, data)
	// The first chunk is served; every request after it looks like a host with
	// nothing mounted at the path.
	var calls int64
	lfsServer.rejectWhen = func(batchRequest) int {
		if atomic.AddInt64(&calls, 1) > 1 {
			return http.StatusNotFound
		}
		return http.StatusOK
	}
	repositoryPath := newRepoWithLFS(t, files)

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil {
		t.Fatal("an endpoint that stops serving the rest should be reported")
	}
	// ErrDisabled is how the mirror layer recognises an expected skip, so the
	// partial-mirror error must not match it through the chain.
	if errors.Is(err, ErrDisabled) || errors.Is(err, ErrNoEndpoint) {
		t.Fatalf("err = %v, want a failure rather than a clean skip for a partial mirror", err)
	}

	// The chunk that was served did reach the mirror.
	firstOID, _ := pointerFor([]byte("object 0"))
	if _, statErr := os.Stat(filepath.Join(repositoryPath, ".git", "lfs", "objects",
		firstOID[0:2], firstOID[2:4], firstOID)); statErr != nil {
		t.Errorf("the served chunk should be mirrored: %v", statErr)
	}
}

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

	// An empty subtree the hostile tree names twice, so the deduplication is
	// exercised without competing with the commit's own trees for the visit.
	empty := &object.Tree{}
	emptyObject := repository.Storer.NewEncodedObject()
	if err := empty.Encode(emptyObject); err != nil {
		t.Fatal(err)
	}
	emptyHash, err := repository.Storer.SetEncodedObject(emptyObject)
	if err != nil {
		t.Fatal(err)
	}

	hostile := &object.Tree{Entries: []object.TreeEntry{
		{Name: "empty-again", Hash: emptyHash, Mode: filemode.Dir},
		{Name: "empty", Hash: emptyHash, Mode: filemode.Dir},
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

	// A ref points at a commit, and the scan reaches trees through commits, so
	// the hostile tree is committed before the ref names it.
	signature := object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	hostileCommit := &object.Commit{
		Author:    signature,
		Committer: signature,
		Message:   "hostile tree",
		TreeHash:  hostileHash,
	}
	commitObject := repository.Storer.NewEncodedObject()
	if err := hostileCommit.Encode(commitObject); err != nil {
		t.Fatal(err)
	}
	hostileCommitHash, err := repository.Storer.SetEncodedObject(commitObject)
	if err != nil {
		t.Fatal(err)
	}

	headRef := plumbing.NewHashReference(plumbing.NewBranchReferenceName("hostile"), hostileCommitHash)
	if err := repository.Storer.SetReference(headRef); err != nil {
		t.Fatal(err)
	}

	scan, err := collectPointers(context.Background(), repository)
	if err != nil {
		t.Fatalf("collectPointers failed on a tree with host-specific names: %v", err)
	}
	if len(scan.pointers) != 1 || scan.pointers[0].oid != oid {
		t.Fatalf("pointers = %+v, want the single pointer %s", scan.pointers, oid)
	}
	// The hostile entry names a blob that was never stored, so the scan reports
	// it rather than quietly reading a smaller set. The empty subtree behind the
	// two directory entries is visited once, so it is not reported as skipped.
	if len(scan.skipped) != 1 || scan.skipped[0].name != `src\windows.cpp` {
		t.Errorf("skipped = %+v, want just the entry whose blob is missing", scan.skipped)
	}
}

// TestCollectPointersReportsUnreadableSubtrees covers a subtree whose object is
// missing — a partial fetch, say. Its pointers cannot be fetched, so the scan
// has to name them as skipped rather than reporting a smaller pointer set as if
// it were the whole truth.
func TestCollectPointersReportsUnreadableSubtrees(t *testing.T) {
	const missingName = "missing"
	repositoryPath := addMissingSubtreeCommit(t, missingName)

	repository, err := git.PlainOpen(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}

	scan, err := collectPointers(context.Background(), repository)
	if err != nil {
		t.Fatalf("a missing subtree should not fail the scan: %v", err)
	}
	if len(scan.skipped) != 1 || scan.skipped[0].name != missingName {
		t.Fatalf("skipped = %+v, want the unreadable subtree named", scan.skipped)
	}
	if scan.skipped[0].err == nil {
		t.Error("the skip should carry the reason it was skipped")
	}
}

// addMissingSubtreeCommit builds a repository whose history names a subtree
// object that was never stored, so the pointer scan has something it cannot
// read, and returns its path.
func addMissingSubtreeCommit(t *testing.T, name string) string {
	t.Helper()

	repositoryPath := newRepoWithLFS(t, map[string]string{"README.md": "plain repo"})
	repository, err := git.PlainOpen(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}

	tree := &object.Tree{Entries: []object.TreeEntry{
		{Name: name, Hash: plumbing.NewHash(strings.Repeat("b", 40)), Mode: filemode.Dir},
	}}
	treeObject := repository.Storer.NewEncodedObject()
	if err := tree.Encode(treeObject); err != nil {
		t.Fatal(err)
	}
	treeHash, err := repository.Storer.SetEncodedObject(treeObject)
	if err != nil {
		t.Fatal(err)
	}

	signature := object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}
	commit := &object.Commit{
		Author:    signature,
		Committer: signature,
		Message:   "point at a missing subtree",
		TreeHash:  treeHash,
	}
	commitObject := repository.Storer.NewEncodedObject()
	if err := commit.Encode(commitObject); err != nil {
		t.Fatal(err)
	}
	commitHash, err := repository.Storer.SetEncodedObject(commitObject)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName("hostile"), commitHash)); err != nil {
		t.Fatal(err)
	}
	return repositoryPath
}

// TestFetchAllFailsWhenTheScanCouldNotReadEverything covers what the mirror
// layer sees when part of the repository cannot be read: the pointers behind it
// cannot be fetched either, so the fetch reports rather than returning success
// for a mirror that is quietly incomplete.
func TestFetchAllFailsWhenTheScanCouldNotReadEverything(t *testing.T) {
	lfsServer := newFakeLFSServer(t, nil)
	repositoryPath := addMissingSubtreeCommit(t, "missing")

	err := NewFetcher().FetchAll(context.Background(), repositoryPath, lfsServer.remoteURL(), "", "")
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Fatalf("FetchAll = %v, want the unreadable entry reported", err)
	}
	if calls := lfsServer.batchCallCount(); calls != 0 {
		t.Errorf("batch calls = %d, want no endpoint work for a scan that cannot complete", calls)
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
// without .git still has to request the suffixed path. Everything else the
// remote URL carries has to survive the rewrite.
func TestDefaultEndpointAddsGitSuffix(t *testing.T) {
	cases := []struct {
		remoteURL string
		want      string
	}{
		{"https://github.com/owner/repo", "https://github.com/owner/repo.git/info/lfs"},
		{"https://github.com/owner/repo.git", "https://github.com/owner/repo.git/info/lfs"},
		{"https://github.com/owner/repo.GIT", "https://github.com/owner/repo.GIT/info/lfs"},
		{"https://github.com/owner/repo/", "https://github.com/owner/repo.git/info/lfs"},
		{"https://git.example.com:8443/group/sub/repo", "https://git.example.com:8443/group/sub/repo.git/info/lfs"},
		{"https://user:secret@git.example.com/owner/repo", "https://user:secret@git.example.com/owner/repo.git/info/lfs"},
		{"https://git.example.com", "https://git.example.com/info/lfs"},
		{"https://git.example.com/", "https://git.example.com/info/lfs"},
		{"https://git.example.com/owner/repo?", "https://git.example.com/owner/repo.git/info/lfs"},
		{"https://git.example.com/owner/repo#frag", "https://git.example.com/owner/repo.git/info/lfs"},
		{"https://git.example.com/owner/re%2Fpo", "https://git.example.com/owner/re%2Fpo.git/info/lfs"},
		{"https://git.example.com/owner/re po", "https://git.example.com/owner/re%20po.git/info/lfs"},
	}

	for _, c := range cases {
		t.Run(redactedURL(c.remoteURL), func(t *testing.T) {
			parsed, err := url.Parse(c.remoteURL)
			if err != nil {
				t.Fatal(err)
			}
			if got := defaultEndpoint(parsed); got != c.want {
				t.Errorf("defaultEndpoint(%q) = %q, want %q", redactedURL(c.remoteURL), redactedURL(got), redactedURL(c.want))
			}
		})
	}
}

// TestResolveEndpointsCollapsesDuplicateCandidates covers remotes that reach the
// LFS API at one path whichever candidate is derived — a remote that already
// carries the repository suffix, and one with no path at all. Probing the same
// URL twice would repeat every request of a whole repository for nothing.
func TestResolveEndpointsCollapsesDuplicateCandidates(t *testing.T) {
	for _, remoteURL := range []string{
		"https://git.example.com/owner/repo.git",
		"https://git.example.com",
	} {
		t.Run(redactedURL(remoteURL), func(t *testing.T) {
			repositoryPath := newRepoWithLFS(t, map[string]string{"README.md": "plain repo"})
			repository, err := git.PlainOpen(repositoryPath)
			if err != nil {
				t.Fatal(err)
			}

			endpoints, err := resolveEndpoints(repository, remoteURL)
			if err != nil {
				t.Fatalf("resolveEndpoints failed: %v", err)
			}
			if len(endpoints) != 1 {
				t.Errorf("endpoints = %q, want one candidate for a remote that has only one path", redactedURL(strings.Join(endpoints, ",")))
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
			name:        "endpoint rooted at the host",
			lfsURL:      "https://example.com:443/",
			remoteURL:   "https://example.com/repo.git",
			wantAddress: "https://example.com",
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

			endpoints, err := resolveEndpoints(repository, c.remoteURL)
			if c.wantReject {
				if err == nil {
					t.Fatalf("resolveEndpoints = %q, want rejection", redactedURL(strings.Join(endpoints, ",")))
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEndpoints failed: %v", err)
			}
			if len(endpoints) != 1 || endpoints[0] != c.wantAddress {
				t.Errorf("endpoints = %q, want just %q", redactedURL(strings.Join(endpoints, ",")), redactedURL(c.wantAddress))
			}
			if lfsServer.batchCallCount() != 0 {
				t.Error("resolveEndpoints must not contact any endpoint")
			}
		})
	}
}
