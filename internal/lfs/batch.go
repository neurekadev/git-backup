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

// probe asks an endpoint for one object to find out whether it serves this
// repository's LFS API at all. Discovery happens once, before any object is
// fetched, so the fetch itself runs against a single known-good endpoint: the
// answer separates "the API answered for this object" — including that the
// server does not have it — from "LFS is switched off here" and from "nothing is
// mounted at this path".
//
// A single object keeps the probe from tripping a server's object limit, so a
// refused probe is about the path rather than the request's shape. A nil return
// therefore means the API root is right, and the object's own fate is the
// fetch's business.
func (c *batchClient) probe(ctx context.Context, endpoint, username, password string, object pointer) error {
	body, err := json.Marshal(batchRequest{
		Operation: "download",
		Transfers: []string{"basic"},
		Objects:   toBatchObjects([]pointer{object}),
	})
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/objects/batch", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", lfsMediaType)
	request.Header.Set("Accept", lfsMediaType)
	if username != "" || password != "" {
		request.SetBasicAuth(username, password)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("batch request: %w", err)
	}
	defer drainAndClose(response)

	switch response.StatusCode {
	case http.StatusOK:
		// The API answered for the object, whether by scheduling it or by
		// reporting that the server does not have it.
		return nil
	case http.StatusForbidden:
		// The forge has LFS switched off for this repository.
		return ErrDisabled
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		// Nothing is mounted at this path: a host that routes by path answers
		// 404, and one that validates the action answers a single-object
		// request with 422.
		return ErrNoEndpoint
	default:
		return fmt.Errorf("batch request failed with status %d", response.StatusCode)
	}
}

// batch submits every pointer for download scheduling.
//
// A status describing the request's shape is reported as errBatchRejected so
// callers can retry the pointers in smaller batches; every other status
// describes the endpoint rather than what was asked of it, so splitting the
// chunk would only repeat the same answer more slowly. Discovery already
// established which endpoint serves the API, so a 403 or 404 here describes a
// service that has stopped answering rather than a path worth retrying.
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

	switch {
	case response.StatusCode == http.StatusOK:
		// Handled below.
	case describesRequestShape(response.StatusCode):
		return nil, fmt.Errorf("%w: status %d", errBatchRejected, response.StatusCode)
	default:
		return nil, fmt.Errorf("batch request failed with status %d", response.StatusCode)
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

// describesRequestShape reports whether a status is how servers answer a request
// they will not process as sent, which a smaller batch may avoid: an unprocessable
// entity, a payload the server considers too large, or a body it cannot accept.
// Credentials, rate limiting, and the endpoint's own failures are not among them.
func describesRequestShape(status int) bool {
	switch status {
	case http.StatusBadRequest,
		http.StatusRequestEntityTooLarge,
		http.StatusUnprocessableEntity,
		http.StatusNotAcceptable,
		http.StatusUnsupportedMediaType:
		return true
	default:
		return false
	}
}

// downloadObjects streams each scheduled object into the repository's LFS
// cache, verifying its SHA-256 as bytes arrive. Objects already cached are
// skipped, so repeated snapshots only download new content.
//
// Every object is attempted whatever the others did, so one bad pointer or one
// transient transfer failure cannot hide its siblings. What failed comes back in
// the three lists: cached for objects already in the cache, unavailable for
// objects the endpoint will not serve, and failed for objects this client could
// not transfer — a corrupt body, a broken connection — which the caller reports
// rather than recording as the endpoint's refusal.
func downloadObjects(
	ctx context.Context,
	client *batchClient,
	store, endpoint, username, password string,
	objects []batchResponseObject,
) (cached, unavailable []*batchObjectError, failed []error) {
	endpointHost := hostOf(endpoint)
	answered := func(object batchResponseObject) *batchObjectError {
		switch {
		case object.Error != nil:
			return &batchObjectError{oid: object.OID, message: object.Error.Message}
		case object.Actions["download"] == nil || object.Actions["download"].Href == "":
			// The server knows the object but scheduled nothing; without an
			// href there is nothing this client can do beyond reporting it.
			return &batchObjectError{oid: object.OID, message: "no download action was scheduled"}
		default:
			return nil
		}
	}

	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return cached, unavailable, append(failed, err)
		}
		if refused := answered(object); refused != nil {
			unavailable = append(unavailable, refused)
			continue
		}
		stored, err := downloadObject(ctx, client.client, store, endpointHost, username, password, object.OID, object.Actions["download"])
		switch {
		case err != nil:
			failed = append(failed, err)
		case stored:
			// Already in the cache: the endpoint answered for it, but this
			// request never streamed it.
			cached = append(cached, &batchObjectError{oid: object.OID, message: "already in the local cache"})
		}
	}
	return cached, unavailable, failed
}

// downloadObject streams one object into the LFS cache, verifying its SHA-256 as
// bytes arrive. It reports whether the object was already cached, so a caller can
// tell an endpoint that streamed the bytes from one that merely answered for
// them.
func downloadObject(
	ctx context.Context,
	client *http.Client,
	store, endpointHost, username, password, oid string,
	action *batchAction,
) (bool, error) {
	destination := filepath.Join(store, oid[0:2], oid[2:4], oid)
	if _, err := os.Stat(destination); err == nil {
		// Already cached by a previous snapshot; git-lfs also skips it.
		return true, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, action.Href, nil)
	if err != nil {
		return false, fmt.Errorf("LFS object %s: %w", shortOID(oid), err)
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
		return false, fmt.Errorf("LFS object %s: %w", shortOID(oid), err)
	}
	defer drainAndClose(response)

	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("LFS object %s download failed with status %d", shortOID(oid), response.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return false, fmt.Errorf("create LFS cache directory: %w", err)
	}

	temp, err := os.CreateTemp(filepath.Dir(destination), ".lfs-download-*")
	if err != nil {
		return false, fmt.Errorf("create LFS temp file: %w", err)
	}
	tempName := temp.Name()

	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(temp, hash), response.Body)
	closeErr := temp.Close()
	if copyErr != nil {
		_ = os.Remove(tempName)
		return false, fmt.Errorf("LFS object %s: %w", shortOID(oid), copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tempName)
		return false, fmt.Errorf("LFS object %s: %w", shortOID(oid), closeErr)
	}

	if actual := hex.EncodeToString(hash.Sum(nil)); actual != oid {
		_ = os.Remove(tempName)
		return false, fmt.Errorf("LFS object %s content hash mismatch", shortOID(oid))
	}

	if err := os.Rename(tempName, destination); err != nil {
		_ = os.Remove(tempName)
		return false, fmt.Errorf("store LFS object %s: %w", shortOID(oid), err)
	}
	_ = size
	return false, nil
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
