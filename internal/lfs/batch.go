package lfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// batchObject is one pointer submitted to the batch API.
type batchObject struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// batchRequest asks the endpoint to schedule basic-transfer downloads.
type batchRequest struct {
	Operation string        `json:"operation"`
	Transfers []string      `json:"transfers"`
	Objects   []batchObject `json:"objects"`
}

// batchAction is one server-provided action, here the basic-transfer download
// instruction with its (typically pre-signed) URL.
type batchAction struct {
	Href   string            `json:"href"`
	Header map[string]string `json:"header"`
}

// batchResponseObject is the server's verdict for one object; exactly one of
// Actions and Error is meaningful.
type batchResponseObject struct {
	OID     string                  `json:"oid"`
	Size    int64                   `json:"size"`
	Actions map[string]*batchAction `json:"actions"`
	Error   *batchError             `json:"error"`
}

type batchError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type batchResponse struct {
	Objects []batchResponseObject `json:"objects"`
}

// errBatchRejected marks a batch request the endpoint answered with an
// unexpected status instead of scheduling the objects. Callers narrow such a
// request down to individual objects, because a rejection is usually one
// object's fault (the endpoint's object limit, a stale pointer) rather than the
// whole batch's.
var errBatchRejected = errors.New("batch request rejected by the endpoint")

// errObjectUnavailable reports that the endpoint answered the batch request but
// will not serve one of the objects it named, so the object cannot be mirrored.
var errObjectUnavailable = errors.New("lfs object unavailable on the remote")

// batchObjectError is one object the endpoint refused: a pointer kept in the
// repository after its object was removed or garbage-collected on the server.
type batchObjectError struct {
	oid     string
	message string
}

func (e *batchObjectError) Error() string {
	return fmt.Sprintf("LFS object %s unavailable: %s", shortOID(e.oid), e.message)
}

func (e *batchObjectError) Unwrap() error { return errObjectUnavailable }

// batchClient performs the LFS batch protocol over HTTP.
type batchClient struct {
	client *http.Client
}

func newBatchClient(client *http.Client) *batchClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Minute}
	}
	return &batchClient{client: client}
}

const lfsMediaType = "application/vnd.git-lfs+json"

// batch submits every pointer for download scheduling. A 403 or 404 from the
// endpoint means the remote has Git LFS switched off, which callers treat as
// an expected skip rather than a failure. Any other unexpected status is
// reported as errBatchRejected so callers can retry the pointers individually.
func (c *batchClient) batch(ctx context.Context, endpoint, username, password string, pointers []pointer) ([]batchResponseObject, error) {
	body, err := json.Marshal(batchRequest{
		Operation: "download",
		Transfers: []string{"basic"},
		Objects:   toBatchObjects(pointers),
	})
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/objects/batch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", lfsMediaType)
	request.Header.Set("Accept", lfsMediaType)
	if username != "" || password != "" {
		request.SetBasicAuth(username, password)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("batch request: %w", err)
	}
	defer drainAndClose(response)

	switch response.StatusCode {
	case http.StatusOK:
		// Handled below.
	case http.StatusForbidden, http.StatusNotFound:
		return nil, ErrDisabled
	default:
		return nil, fmt.Errorf("%w: status %d", errBatchRejected, response.StatusCode)
	}

	var decoded batchResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 512<<20)).Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode batch response: %w", err)
	}
	if len(decoded.Objects) != len(pointers) {
		return nil, fmt.Errorf("batch response has %d objects for %d pointers", len(decoded.Objects), len(pointers))
	}
	return decoded.Objects, nil
}

// downloadObjects streams each scheduled object into the repository's LFS
// cache, verifying its SHA-256 as bytes arrive. Objects already cached are
// skipped, so repeated snapshots only download new content.
func downloadObjects(
	ctx context.Context,
	client *batchClient,
	store, endpoint, username, password string,
	objects []batchResponseObject,
) error {
	endpointHost := hostOf(endpoint)
	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if object.Error != nil {
			return &batchObjectError{oid: object.OID, message: object.Error.Message}
		}

		action := object.Actions["download"]
		if action == nil || action.Href == "" {
			// The server knows the object but scheduled nothing; without a
			// href there is nothing this client can do beyond reporting it.
			return &batchObjectError{oid: object.OID, message: "no download action was scheduled"}
		}

		if err := downloadObject(ctx, client.client, store, endpointHost, username, password, object.OID, action); err != nil {
			return err
		}
	}
	return nil
}

func downloadObject(
	ctx context.Context,
	client *http.Client,
	store, endpointHost, username, password, oid string,
	action *batchAction,
) error {
	destination := filepath.Join(store, oid[0:2], oid[2:4], oid)
	if _, err := os.Stat(destination); err == nil {
		// Already cached by a previous snapshot; git-lfs also skips it.
		return nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, action.Href, nil)
	if err != nil {
		return fmt.Errorf("LFS object %s: %w", shortOID(oid), err)
	}
	for key, value := range action.Header {
		request.Header.Set(key, value)
	}
	// Pre-signed download URLs carry their own authorization; the basic
	// credential only applies while the request stays on the LFS endpoint's
	// host.
	if hostOf(action.Href) == endpointHost && (username != "" || password != "") {
		request.SetBasicAuth(username, password)
	}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("LFS object %s: %w", shortOID(oid), err)
	}
	defer drainAndClose(response)

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("LFS object %s download failed with status %d", shortOID(oid), response.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return fmt.Errorf("create LFS cache directory: %w", err)
	}

	temp, err := os.CreateTemp(filepath.Dir(destination), ".lfs-download-*")
	if err != nil {
		return fmt.Errorf("create LFS temp file: %w", err)
	}
	tempName := temp.Name()

	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temp, hash), response.Body)
	closeErr := temp.Close()
	if copyErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("LFS object %s: %w", shortOID(oid), copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("LFS object %s: %w", shortOID(oid), closeErr)
	}

	if actual := hex.EncodeToString(hash.Sum(nil)); actual != oid {
		_ = os.Remove(tempName)
		return fmt.Errorf("LFS object %s content hash mismatch", shortOID(oid))
	}

	if err := os.Rename(tempName, destination); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("store LFS object %s: %w", shortOID(oid), err)
	}
	_ = size
	return nil
}

func toBatchObjects(pointers []pointer) []batchObject {
	objects := make([]batchObject, 0, len(pointers))
	for _, item := range pointers {
		objects = append(objects, batchObject{OID: item.oid, Size: item.size})
	}
	return objects
}

func hostOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func shortOID(oid string) string {
	if len(oid) <= 12 {
		return oid
	}
	return oid[:12]
}

// drainAndClose discards a small response body and closes it so the
// underlying connection can be reused.
func drainAndClose(response *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	_ = response.Body.Close()
}
