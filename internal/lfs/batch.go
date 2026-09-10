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
	"strings"
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
//
// The expiry fields matter to a long run: a pre-signed URL stops working once it
// lapses, and the server is the only party that can issue a fresh one.
type batchAction struct {
	Href      string            `json:"href"`
	Header    map[string]string `json:"header"`
	ExpiresIn int64             `json:"expires_in"`
	ExpiresAt string            `json:"expires_at"`
}

// expired reports whether the action's URL has already lapsed. A past ExpiresAt
// is authoritative; otherwise the relative expiry is measured from now.
func (a *batchAction) expired() bool {
	if a.ExpiresAt != "" {
		if at, err := time.Parse(time.RFC3339, a.ExpiresAt); err == nil {
			return !at.After(time.Now())
		}
	}
	return a.ExpiresIn < 0
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

// authorize offers the credentials to a request when there are any to offer.
// Every batch request goes out authenticated rather than waiting for a 401,
// because a forge is free to answer 403 to an anonymous request, and a 403 is
// also how a repository with LFS switched off answers.
func (c credentials) authorize(request *http.Request) {
	if !c.available() {
		return
	}
	request.SetBasicAuth(c.username, c.password)
}

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
//
// The credentials are offered on the first request when there are any. Waiting
// for a 401 to offer them would read a forge that answers 403 to anonymous
// requests as a repository with LFS switched off, which backs it up without its
// LFS content instead of reporting that the credential was refused.
func (c *batchClient) probe(ctx context.Context, endpoint string, creds credentials, object pointer) error {
	return c.doProbe(ctx, endpoint, creds, object)
}

// doProbe performs one probe request, offering the credentials when there are
// any to offer.
func (c *batchClient) doProbe(ctx context.Context, endpoint string, creds credentials, object pointer) error {
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
	creds.authorize(request)

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
	case http.StatusUnauthorized:
		// The endpoint refused what it was sent, and the credentials were
		// already offered, so this is reported rather than retried: repeating
		// the request would send the same credentials again. Reading it as a
		// path problem would be worse still, because the path answered.
		return fmt.Errorf("batch request failed with status %d", response.StatusCode)
	case http.StatusForbidden:
		// Two different things answer 403: a forge saying LFS is switched off
		// for this repository, and a host page refusing a path it does not
		// serve. The LFS API explains itself — in JSON, and sometimes with no
		// body at all, which is still a verdict about the repository — while an
		// edge page does not.
		return classifyRefusal(response, ErrDisabled)
	case http.StatusNotFound:
		// Nothing is mounted at this path: a host that routes by path answers
		// 404.
		return ErrNoEndpoint
	case http.StatusUnprocessableEntity:
		// Unprocessable is how an edge refuses a path it does not route as much
		// as it is how the API refuses a request's shape. A single object cannot
		// trip an object limit, so a page here is a wrong path and anything else
		// is the API refusing the probe.
		return classifyRefusal(response, fmt.Errorf("batch request failed with status %d", response.StatusCode))
	default:
		// Every other status describes the endpoint or the credential rather
		// than the path — a rate limit, an authentication failure, the server's
		// own error — so it stays a reported failure. Reading an edge's error
		// page as "no endpoint here" would let the mirror layer record a broken
		// or unauthorized service as a repository with LFS switched off.
		return fmt.Errorf("batch request failed with status %d", response.StatusCode)
	}
}

// classifyRefusal reads a refusal the API did not phrase as a verdict about one
// object. Markup means a host page answered — the path is not the API — and
// anything else is the API speaking, which the caller reads as verdict.
func classifyRefusal(response *http.Response, verdict error) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err == nil && looksLikeHTML(body) {
		return ErrNoEndpoint
	}
	return verdict
}

// credentials are the HTTP basic-auth pair the remote's own API accepts. They
// travel as a value rather than as raw strings because a client may need to
// offer them more than once: the batch API answers 401 when credentials are
// needed but were not sent, and the request is then retried once with them.
type credentials struct {
	username string
	password string
}

// available reports whether there is anything to offer. A request with no
// credentials to offer goes out anonymous, because there is nothing to add.
func (c credentials) available() bool {
	return c.username != "" || c.password != ""
}

// batch submits every pointer for download scheduling.
//
// A status describing the request's shape is reported as errBatchRejected so
// callers can retry the pointers in smaller batches; every other status
// describes the endpoint rather than what was asked of it, so splitting the
// chunk would only repeat the same answer more slowly. Discovery already
// established which endpoint serves the API, so a 403 or 404 here describes a
// service that has stopped answering rather than a path worth retrying.
//
// A 401 means the endpoint would not accept what was sent, so it is reported
// rather than retried: the credentials were already offered, and repeating the
// request would send the same ones.
func (c *batchClient) batch(ctx context.Context, creds credentials, endpoint string, pointers []pointer) ([]batchResponseObject, error) {
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
	creds.authorize(request)

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

// looksLikeHTML reports whether a body is a markup document, which is what an
// edge or proxy answers with and what the LFS API never does. A JSON document or
// an empty body is therefore read as the API speaking; markup is read as the path
// being refused by something that is not the API.
func looksLikeHTML(body []byte) bool {
	trimmed := bytes.TrimSpace(bytes.ToLower(body))
	return bytes.HasPrefix(trimmed, []byte("<!doctype")) || bytes.HasPrefix(trimmed, []byte("<html"))
}

// downloadObjects streams each scheduled object into the repository's LFS
// cache, verifying its SHA-256 as bytes arrive. Objects already cached are
// skipped, so repeated snapshots only download new content.
//
// Every object is attempted whatever the others did, so one bad pointer or one
// transient transfer failure cannot hide its siblings. What could not be fetched
// comes back in three lists: expired for objects whose scheduled URL had already
// lapsed, which the caller asks the endpoint about again; unavailable for objects
// the endpoint will not serve; and failed for objects this client could not
// transfer — a corrupt body, a broken connection — which the caller reports
// rather than recording as the endpoint's refusal.
func downloadObjects(
	ctx context.Context,
	client *batchClient,
	store, endpoint string,
	creds credentials,
	want []pointer,
	objects []batchResponseObject,
) (expired []pointer, unavailable []*batchObjectError, failed []error) {
	endpointHost := hostOf(endpoint)
	// The endpoint's OIDs are used as path components and sliced for the shard
	// directories, so an object that was not asked for — or one whose OID is not
	// a SHA-256 digest — is refused before any of that: a short OID would panic
	// the slice, and a crafted one could name a path outside the store.
	requested := make(map[string]bool, len(want))
	wantSize := make(map[string]int64, len(want))
	for _, pointer := range want {
		requested[pointer.oid] = true
		wantSize[pointer.oid] = pointer.size
	}
	// answered also returns the canonical spelling of the object's OID: the
	// pointer's OIDs are lowercase, while an endpoint may echo a valid digest in
	// upper case. The OID is a path component and the store is keyed by it, so
	// the response is folded to the spelling the store already uses.
	answered := func(object batchResponseObject) (string, *batchObjectError) {
		switch {
		case object.Error != nil:
			return "", &batchObjectError{oid: object.OID, message: object.Error.Message}
		case object.Actions["download"] == nil || object.Actions["download"].Href == "":
			// The server knows the object but scheduled nothing; without an
			// href there is nothing this client can do beyond reporting it.
			return "", &batchObjectError{oid: object.OID, message: "no download action was scheduled"}
		case !isSHA256Hex(object.OID):
			return "", &batchObjectError{oid: shortOID(object.OID), message: "the endpoint described an object whose oid is not a sha256 digest"}
		}
		oid := strings.ToLower(object.OID)
		if !requested[oid] {
			return "", &batchObjectError{oid: shortOID(object.OID), message: "the endpoint described an object that was not requested"}
		}
		return oid, nil
	}

	for _, object := range objects {
		if err := ctx.Err(); err != nil {
			return expired, unavailable, append(failed, err)
		}
		oid, refused := answered(object)
		if refused != nil {
			unavailable = append(unavailable, refused)
			continue
		}
		// The pointer file's own size is authoritative, since it is what the
		// repository records about the object; the endpoint's stands in only
		// when the pointer did not state one.
		size := object.Size
		if wanted, known := wantSize[oid]; known && wanted > 0 {
			size = wanted
		}
		if cached, err := os.Stat(filepath.Join(store, oid[0:2], oid[2:4], oid)); err == nil &&
			cached.Mode().IsRegular() && (size == 0 || cached.Size() == size) {
			// Already cached by a previous snapshot; git-lfs also skips it, and
			// content already held needs no fresh URL, so this is settled before
			// the expiry below can send it back for rescheduling. A file of a
			// length the recorded size contradicts is not this object, so it
			// falls through to the download, which verifies the digest as bytes
			// arrive. No size anywhere leaves the length unstated rather than
			// contradicted, and re-downloading content the store already holds
			// would risk failing over it.
			continue
		}
		action := object.Actions["download"]
		if action.expired() {
			// The URL lapsed before it was used — a long scan, a slow batch, a
			// small expires_in — so the object needs a fresh one rather than a
			// transfer that can only fail. The resolved size travels with it, so
			// the refresh request and the pass over its answer keep the length
			// the pointer records rather than falling back to an endpoint that
			// stated none.
			expired = append(expired, pointer{oid: oid, size: size})
			continue
		}
		if err := downloadObject(ctx, client.client, store, endpointHost, creds, oid, action); err != nil {
			failed = append(failed, err)
		}
	}
	return expired, unavailable, failed
}

// downloadObject streams one object into the LFS cache, verifying its SHA-256 as
// bytes arrive.
func downloadObject(
	ctx context.Context,
	client *http.Client,
	store, endpointHost string,
	creds credentials,
	oid string,
	action *batchAction,
) error {
	destination := filepath.Join(store, oid[0:2], oid[2:4], oid)

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
	if hostOf(action.Href) == endpointHost && creds.available() {
		request.SetBasicAuth(creds.username, creds.password)
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
