// Package store provides unified state management for opnix secrets.
// It handles both caching (reducing 1Password API calls) and change detection
// (for systemd service restarts) in a single, thread-safe store.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/brizzbuzz/opnix/internal/errors"
)

// DefaultStateFile is the default location for the unified state file
const DefaultStateFile = "/var/lib/opnix/state.json"

// Legacy file path for auto-migration from upstream opnix
const legacyHashStoreFile = "/var/lib/opnix/secret-hashes.json"

// SecretEntry represents a secret's state, combining caching and change detection data.
type SecretEntry struct {
	// Reference is the 1Password reference (e.g., op://Vault/Item/field)
	// Used to detect configuration changes
	Reference string `json:"reference"`

	// ContentHash is the SHA-256 hash of the secret's content
	// Used for both caching validation and change detection
	ContentHash string `json:"content_hash"`

	// LastFetched is when the secret was last retrieved from 1Password
	// Used for TTL-based cache expiration
	LastFetched time.Time `json:"last_fetched"`
}

// SecretStore manages secret state for caching and change detection.
// It is safe for concurrent access.
type SecretStore struct {
	// Entries maps output file paths to their state entries
	Entries map[string]SecretEntry `json:"entries"`

	// path is the file path where the store is persisted
	path string

	// mu protects concurrent access to Entries
	mu sync.RWMutex
}

// New creates a new empty store that will be persisted at the given path.
func New(path string) *SecretStore {
	return &SecretStore{
		Entries: make(map[string]SecretEntry),
		path:    path,
	}
}

// Load reads an existing store from disk. If the file doesn't exist,
// it attempts to auto-migrate from legacy cache and hash store files.
// If the file is corrupted, it returns an empty store for graceful recovery.
func Load(path string) (*SecretStore, error) {
	store := New(path)

	// Try loading the unified state file first
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, store); err != nil {
			// Corrupted file - return empty store for graceful recovery
			return New(path), nil
		}

		// Ensure map is initialized even if JSON had null
		if store.Entries == nil {
			store.Entries = make(map[string]SecretEntry)
		}

		store.path = path
		return store, nil
	} else if !os.IsNotExist(err) {
		// Error other than "not exist" - return empty store
		return store, nil
	}

	// State file doesn't exist - try auto-migration from upstream's HashStore
	if err := store.migrateFromLegacyHashStore(legacyHashStoreFile); err == nil && len(store.Entries) > 0 {
		if err := store.Save(); err == nil {
			// Successfully saved - remove legacy file
			_ = os.Remove(legacyHashStoreFile)
		}
	}

	return store, nil
}

// legacySecretHash represents upstream's secret-hashes.json entry format
type legacySecretHash struct {
	Path         string    `json:"path"`
	Hash         string    `json:"hash"`
	LastModified time.Time `json:"lastModified"`
}

// legacyHashStore represents upstream's secret-hashes.json format
type legacyHashStore struct {
	Hashes map[string]legacySecretHash `json:"hashes"`
}

// migrateFromLegacyHashStore migrates data from upstream's secret-hashes.json format
func (s *SecretStore) migrateFromLegacyHashStore(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var hashStore legacyHashStore
	if err := json.Unmarshal(data, &hashStore); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for path, hash := range hashStore.Hashes {
		if existing, exists := s.Entries[path]; exists {
			// Entry exists from cache migration - update hash if needed
			if existing.ContentHash == "" {
				existing.ContentHash = hash.Hash
				s.Entries[path] = existing
			}
		} else {
			// New entry from hash store
			s.Entries[path] = SecretEntry{
				ContentHash: hash.Hash,
				LastFetched: hash.LastModified,
			}
		}
	}

	return nil
}

// Save persists the store to disk. It creates parent directories if needed
// and uses atomic write (temp file + rename) for safety.
func (s *SecretStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create parent directory if it doesn't exist
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.FileOperationError(
			"Creating state directory",
			dir,
			"Failed to create directory for state file",
			err,
		)
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return errors.ConfigError(
			"Serializing state",
			"Failed to marshal state to JSON",
			err,
		)
	}

	// Write atomically by writing to temp file then renaming
	tempPath := s.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return errors.FileOperationError(
			"Writing state file",
			tempPath,
			"Failed to write temporary state file",
			err,
		)
	}

	if err := os.Rename(tempPath, s.path); err != nil {
		// Clean up temp file on failure
		_ = os.Remove(tempPath)
		return errors.FileOperationError(
			"Saving state file",
			s.path,
			"Failed to rename temporary state file",
			err,
		)
	}

	return nil
}

// NeedsFetch determines if a secret should be fetched from 1Password.
// It returns true (needs fetch) if:
//   - No entry exists for this path
//   - The reference has changed (secret rotated in config)
//   - The output file doesn't exist
//   - The output file's content doesn't match the stored hash
//   - The TTL has expired
func (s *SecretStore) NeedsFetch(outputPath, reference string, ttl time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.Entries[outputPath]
	if !exists {
		return true // Never cached
	}

	// Check if reference changed (config was updated)
	if entry.Reference != reference {
		return true
	}

	// Check if file exists and matches stored hash
	if !s.fileMatchesHash(outputPath, entry.ContentHash) {
		return true
	}

	// Check if TTL has expired
	if time.Since(entry.LastFetched) > ttl {
		return true
	}

	return false
}

// RecordFetch records a successfully fetched secret in the store.
// The value parameter is the secret content (used to compute the hash).
func (s *SecretStore) RecordFetch(outputPath, reference, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Entries[outputPath] = SecretEntry{
		Reference:   reference,
		ContentHash: ComputeHash(value),
		LastFetched: time.Now(),
	}
}

// HasChanged checks if a secret's content has changed since last recorded.
// Returns true if:
//   - No entry exists for this path (first time)
//   - The file's current content hash doesn't match the stored hash
//
// This method also updates the stored hash if a change is detected.
func (s *SecretStore) HasChanged(filePath string) (bool, error) {
	// Calculate current hash from file
	currentHash, err := ComputeFileHash(filePath)
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.Entries[filePath]
	if !exists {
		// First time seeing this file - it's "changed"
		s.Entries[filePath] = SecretEntry{
			ContentHash: currentHash,
			LastFetched: time.Now(),
		}
		return true, nil
	}

	// Compare hashes
	if entry.ContentHash != currentHash {
		// Content changed - update stored hash
		entry.ContentHash = currentHash
		entry.LastFetched = time.Now()
		s.Entries[filePath] = entry
		return true, nil
	}

	// No change detected
	return false, nil
}

// GetEntry returns the entry for a given path, if it exists.
func (s *SecretStore) GetEntry(path string) (SecretEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.Entries[path]
	return entry, exists
}

// Remove deletes an entry for the given path.
func (s *SecretStore) Remove(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.Entries, path)
}

// Size returns the number of entries in the store.
func (s *SecretStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Entries)
}

// Clear removes all entries from the store.
func (s *SecretStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Entries = make(map[string]SecretEntry)
}

// fileMatchesHash checks if a file exists and its content matches the expected hash.
func (s *SecretStore) fileMatchesHash(path, expectedHash string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false // File doesn't exist or can't be read
	}

	actualHash := ComputeHash(string(data))
	return actualHash == expectedHash
}

// ComputeHash returns the SHA-256 hash of the given content as a hex string.
func ComputeHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// ComputeFileHash calculates the SHA-256 hash of a file's content.
func ComputeFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", errors.FileOperationError(
			"Opening file for hashing",
			filePath,
			"Failed to open file for hash calculation",
			err,
		)
	}
	defer func() { _ = file.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", errors.FileOperationError(
			"Reading file for hashing",
			filePath,
			"Failed to read file content for hash calculation",
			err,
		)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Path returns the file path where the store is persisted.
func (s *SecretStore) Path() string {
	return s.path
}

// MigrateFromCustomHashStorePath attempts to migrate from a custom HashStore location.
// This is useful when the user has configured a non-default hashFile path in upstream opnix.
func (s *SecretStore) MigrateFromCustomHashStorePath(hashStorePath string) error {
	if hashStorePath == "" {
		return nil
	}

	if err := s.migrateFromLegacyHashStore(hashStorePath); err != nil {
		return err
	}

	_ = os.Remove(hashStorePath)
	return s.Save()
}

// String returns a debug string representation of the store.
func (s *SecretStore) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("SecretStore{path=%s, entries=%d}", s.path, len(s.Entries))
}
