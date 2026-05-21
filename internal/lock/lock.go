// Package lock manages the undep.lock integrity pinning file.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LockEntry represents one inlined dependency in the lockfile.
type LockEntry struct {
	Path      string            `json:"path"`
	Version   string            `json:"version"`
	License   string            `json:"license"`
	Files     map[string]string `json:"files"`
	InlinedAt string            `json:"inlined_at"`
}

// LockFile is the complete lockfile state.
type LockFile struct {
	Version   string           `json:"version"`
	Generated string           `json:"generated"`
	Entries   map[string]LockEntry `json:"entries"`
}

// LockDiff compares two lockfiles.
type LockDiff struct {
	Added     []string
	Removed   []string
	Updated   []string
	Unchanged []string
}

// NewLockFile creates an empty lockfile with version "1.0" and current timestamp.
func NewLockFile() *LockFile {
	return &LockFile{
		Version:   "1.0",
		Generated: time.Now().UTC().Format(time.RFC3339),
		Entries:   make(map[string]LockEntry),
	}
}

// AddEntry adds or updates a dependency entry with current timestamp.
func (lf *LockFile) AddEntry(path, version, license string, files map[string]string) {
	lf.Entries[path] = LockEntry{
		Path:      path,
		Version:   version,
		License:   license,
		Files:     files,
		InlinedAt: time.Now().UTC().Format(time.RFC3339),
	}
	lf.Generated = time.Now().UTC().Format(time.RFC3339)
}

// Write writes the lockfile as indented JSON.
func (lf *LockFile) Write(path string) error {
	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal lockfile: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write lockfile: %w", err)
	}
	return nil
}

// LoadLockFile reads a lockfile from disk.
func LoadLockFile(path string) (*LockFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lockfile: %w", err)
	}
	var lf LockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse lockfile: %w", err)
	}
	return &lf, nil
}

// Diff compares two lockfiles and returns what changed.
func (lf *LockFile) Diff(other *LockFile) LockDiff {
	var d LockDiff

	for path := range other.Entries {
		if existing, ok := lf.Entries[path]; ok {
			if existing.Version != other.Entries[path].Version || !mapEqual(existing.Files, other.Entries[path].Files) {
				d.Updated = append(d.Updated, path)
			} else {
				d.Unchanged = append(d.Unchanged, path)
			}
		} else {
			d.Added = append(d.Added, path)
		}
	}

	for path := range lf.Entries {
		if _, ok := other.Entries[path]; !ok {
			d.Removed = append(d.Removed, path)
		}
	}

	return d
}

// VerifyIntegrity hashes every inlined file on disk and compares to stored hashes.
// Returns list of paths with mismatches.
func (lf *LockFile) VerifyIntegrity(projectRoot string) []string {
	var mismatches []string

	for path, entry := range lf.Entries {
		for relPath, expectedHash := range entry.Files {
			diskPath := filepath.Join(projectRoot, relPath)
			actualHash, err := ComputeFileSHA256(diskPath)
			if err != nil {
				mismatches = append(mismatches, fmt.Sprintf("%s (%s: %v)", path, relPath, err))
				continue
			}
			if actualHash != expectedHash {
				mismatches = append(mismatches, fmt.Sprintf("%s (%s: expected %s, got %s)", path, relPath, expectedHash[:16]+"...", actualHash[:16]+"..."))
			}
		}
	}

	return mismatches
}

// ComputeFileSHA256 computes the SHA-256 hex digest of a file.
func ComputeFileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func mapEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}