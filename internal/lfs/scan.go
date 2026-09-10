package lfs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// pointer is one LFS pointer discovered in a tree.
type pointer struct {
	oid  string // sha256 hex, lowercase
	size int64
}

// pointerVersionValue is the version scheme URI on the first line of every
// LFS pointer file.
const pointerVersionValue = "https://git-lfs.github.com/spec/v1"

// pointerMaxBytes bounds pointer-file reads; real pointers are ~130 bytes.
const pointerMaxBytes = 4 * 1024

// collectPointers scans every ref's commit history and tree for LFS pointer
// blobs, deduplicating commits, trees, and blobs across refs so each object is
// inspected once. Commit history is traversed explicitly (rather than per-ref
// iterators) so a repository with many refs costs one pass over its history,
// not one per ref.
func collectPointers(ctx context.Context, repository *git.Repository) ([]pointer, error) {
	seenCommits := make(map[plumbing.Hash]struct{})
	seenTrees := make(map[plumbing.Hash]bool)
	seenBlobs := make(map[plumbing.Hash]struct{})

	var pointers []pointer
	seenPointers := make(map[string]struct{})

	enqueue := func(queue []plumbing.Hash, hash plumbing.Hash) []plumbing.Hash {
		if hash.IsZero() {
			return queue
		}
		if _, seen := seenCommits[hash]; seen {
			return queue
		}
		return append(queue, hash)
	}

	queue := make([]plumbing.Hash, 0, 64)
	refs, err := repository.References()
	if err != nil {
		return nil, err
	}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Type() == plumbing.SymbolicReference || ref.Name().IsRemote() {
			return nil
		}
		queue = enqueue(queue, peelToCommitHash(repository, ref.Hash()))
		return ctx.Err()
	})
	if err != nil {
		return nil, err
	}

	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		hash := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, seen := seenCommits[hash]; seen {
			continue
		}
		seenCommits[hash] = struct{}{}

		commit, err := repository.CommitObject(hash)
		if err != nil {
			// The ref's tip resolved to something else (or history is
			// partially fetched); skip this commit rather than failing the
			// whole scan.
			continue
		}

		if err := scanTree(repository, commit.TreeHash, seenTrees, seenBlobs, seenPointers, &pointers); err != nil {
			return nil, err
		}

		for _, parent := range commit.ParentHashes {
			queue = enqueue(queue, parent)
		}
	}

	return pointers, nil
}

// peelToCommitHash resolves a ref tip hash to the commit it designates,
// unwrapping annotated tags. A zero hash means "not a commit".
func peelToCommitHash(repository *git.Repository, hash plumbing.Hash) plumbing.Hash {
	commit, err := repository.CommitObject(hash)
	if err == nil {
		return commit.Hash
	}

	tag, err := repository.TagObject(hash)
	if err != nil {
		return plumbing.ZeroHash
	}
	switch tag.TargetType {
	case plumbing.CommitObject:
		return tag.Target
	case plumbing.TagObject:
		return peelToCommitHash(repository, tag.Target)
	default:
		return plumbing.ZeroHash
	}
}

// scanTree collects pointers from every blob under treeHash, descending into
// subtrees iteratively.
//
// Subtrees are walked from their tree objects directly rather than through
// object.TreeWalker: that walker validates each entry against the rules for
// materialising a working tree, so a repository containing a path that is
// illegal on the host — a backslash in an entry name on Windows, for instance —
// would abort the whole backup even though the mirror clones and uploads
// perfectly well. A tree object only ever holds entry names and subtree hashes,
// so enumerating them needs no path handling at all. seenTrees bounds the walk
// for repositories whose history repeats or self-references a tree, and makes
// the cross-ref scan visit each tree once (see collectPointers).
func scanTree(
	repository *git.Repository,
	treeHash plumbing.Hash,
	seenTrees map[plumbing.Hash]bool, seenBlobs map[plumbing.Hash]struct{},
	seenPointers map[string]struct{},
	pointers *[]pointer,
) error {
	tree, err := repository.TreeObject(treeHash)
	if err != nil {
		return fmt.Errorf("read tree: %w", err)
	}

	pending := []*object.Tree{tree}
	seenTrees[treeHash] = true

	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]

		for _, entry := range current.Entries {
			if entry.Mode == filemode.Dir {
				if seenTrees[entry.Hash] {
					continue
				}
				seenTrees[entry.Hash] = true

				subtree, err := repository.TreeObject(entry.Hash)
				if err != nil {
					// A subtree missing from a partial fetch costs its
					// pointers but leaves the rest of the scan intact.
					continue
				}
				pending = append(pending, subtree)
				continue
			}
			if !entry.Mode.IsFile() {
				continue
			}
			if _, seen := seenBlobs[entry.Hash]; seen {
				continue
			}
			seenBlobs[entry.Hash] = struct{}{}

			blob, err := repository.BlobObject(entry.Hash)
			if err != nil {
				continue
			}
			if blob.Size > pointerMaxBytes {
				continue
			}

			reader, err := blob.Reader()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(io.LimitReader(reader, pointerMaxBytes))
			_ = reader.Close()
			if err != nil {
				continue
			}

			if parsed, ok := parsePointer(content); ok {
				if _, duplicate := seenPointers[parsed.oid]; !duplicate {
					seenPointers[parsed.oid] = struct{}{}
					*pointers = append(*pointers, parsed)
				}
			}
		}
	}

	return nil
}

// parsePointer parses an LFS pointer file: the version line followed by
// key/value pairs, of which oid and size are required. Content that merely
// resembles a pointer is ignored.
func parsePointer(content []byte) (pointer, bool) {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	scanner.Buffer(make([]byte, 0, pointerMaxBytes), pointerMaxBytes)

	var parsed pointer
	var sawVersion, sawSize bool
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, " ")
		if !found {
			return pointer{}, false
		}
		switch name {
		case "version":
			if value != pointerVersionValue {
				return pointer{}, false
			}
			sawVersion = true
		case "oid":
			oid, isSHA256 := strings.CutPrefix(value, "sha256:")
			if !isSHA256 || !isSHA256Hex(oid) {
				return pointer{}, false
			}
			parsed.oid = strings.ToLower(oid)
		case "size":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil || size < 0 {
				return pointer{}, false
			}
			parsed.size = size
			sawSize = true
		default:
			// Unknown extension fields are permitted by the pointer spec.
		}
	}
	if !sawVersion || parsed.oid == "" || !sawSize {
		return pointer{}, false
	}
	return parsed, true
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}
