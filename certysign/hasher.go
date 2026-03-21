package certysign

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
)

// HashResult holds the output of a document hashing operation.
type HashResult struct {
	// Hash is the hex-encoded digest.
	Hash string `json:"hash"`
	// Algorithm is the hashing algorithm used (e.g. "sha256").
	Algorithm string `json:"algorithm"`
	// Size is the document size in bytes.
	Size int64 `json:"size"`
	// FileName is the source file name (only set when hashing from a path).
	FileName string `json:"fileName,omitempty"`
}

// HashDocument matches the Node SDK hashMany input shape.
type HashDocument struct {
	Data     []byte
	FileName string
}

// DocumentHasher provides local document hashing without any network calls.
// It is the Go equivalent of the JS DocumentHasher class.
type DocumentHasher struct{}

func newDocumentHasher() *DocumentHasher {
	return &DocumentHasher{}
}

// Hash computes the hash of raw document bytes.
//
// algorithm: "sha256" (default) | "sha384" | "sha512"
func (d *DocumentHasher) Hash(data []byte, algorithm string) (*HashResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("certysign: Hash: data must not be empty")
	}
	if algorithm == "" {
		algorithm = "sha256"
	}
	h, err := newHasher(algorithm)
	if err != nil {
		return nil, err
	}
	h.Write(data)
	return &HashResult{
		Hash:      hex.EncodeToString(h.Sum(nil)),
		Algorithm: algorithm,
		Size:      int64(len(data)),
	}, nil
}

// HashFile reads a file from disk and computes its hash.
//
// algorithm: "sha256" (default) | "sha384" | "sha512"
func (d *DocumentHasher) HashFile(filePath, algorithm string) (*HashResult, error) {
	if filePath == "" {
		return nil, fmt.Errorf("certysign: HashFile: filePath is required")
	}
	if algorithm == "" {
		algorithm = "sha256"
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("certysign: HashFile: open %s: %w", filePath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("certysign: HashFile: stat %s: %w", filePath, err)
	}

	h, err := newHasher(algorithm)
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("certysign: HashFile: read %s: %w", filePath, err)
	}

	return &HashResult{
		Hash:      hex.EncodeToString(h.Sum(nil)),
		Algorithm: algorithm,
		Size:      info.Size(),
		FileName:  filepath.Base(filePath),
	}, nil
}

// HashMany computes the hash of each document in the provided list.
//
// This mirrors the Node SDK shape: each entry carries document bytes and an
// optional file name.
func (d *DocumentHasher) HashMany(docs []HashDocument, algorithm string) ([]*HashResult, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("certysign: HashMany: docs must not be empty")
	}
	results := make([]*HashResult, 0, len(docs))
	for i, doc := range docs {
		r, err := d.Hash(doc.Data, algorithm)
		if err != nil {
			return nil, fmt.Errorf("certysign: HashMany: entry %d: %w", i, err)
		}
		r.FileName = doc.FileName
		results = append(results, r)
	}
	return results, nil
}

// HashFiles computes the hash of each file at the given paths.
func (d *DocumentHasher) HashFiles(filePaths []string, algorithm string) ([]*HashResult, error) {
	if len(filePaths) == 0 {
		return nil, fmt.Errorf("certysign: HashFiles: filePaths must not be empty")
	}
	results := make([]*HashResult, 0, len(filePaths))
	for _, p := range filePaths {
		r, err := d.HashFile(p, algorithm)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

func newHasher(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("certysign: unsupported hash algorithm %q — use sha256, sha384, or sha512", algorithm)
	}
}
