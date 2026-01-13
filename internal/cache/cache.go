// Package cache provides smart caching for 1Password secrets to reduce API calls.
// It tracks fetched secrets and skips re-fetching when the cached version is still valid.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/brizzbuzz/opnix/internal/errors"
)

// Entry represents a cached secret with metadata for freshness checking.
type Entry struct {
	// Reference is the 1Password reference (e.g., op://Vault/Item/field)
	Reference string `json:"reference"`

	// ContentHash is the SHA256 hash of the secret value
	ContentHash string `json:"content_hash"`

	// LastFetched is when the secret was last retrieved from 1Password
	LastFetched time.Time `json:"last_fetched"`
}

// Cache manages cached secret metadata to avoid unnecessary 1Password API calls.
// It is safe for concurrent access.
type Cache struct {
	// Entries maps output file paths to their cache entries
	Entries map[string]Entry `json:"entries"`

	// path is the file path where the cache is persisted
	path string

	// mu protects concurrent access to Entries
	mu sync.RWMutex
}

// New creates a new empty cache that will be persisted at the given path.
func New(path string) *Cache {
	return &Cache{
		Entries: make(map[string]Entry),
		path:    path,
	}
}

// Load reads an existing cache from disk. If the file doesn't exist or is
// corrupted, it returns an empty cache (not an error) to allow graceful recovery.
func Load(path string) (*Cache, error) {
	cache := New(path)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No cache file yet - this is fine, return empty cache
			return cache, nil
		}
		// Log warning but continue with empty cache
		return cache, nil
	}

	if err := json.Unmarshal(data, cache); err != nil {
		// Corrupted cache file - log warning and return empty cache
		// This allows recovery from corruption without failing the entire operation
		return New(path), nil
	}

	// Ensure map is initialized even if JSON had null
	if cache.Entries == nil {
		cache.Entries = make(map[string]Entry)
	}

	cache.path = path
	return cache, nil
}

// Save persists the cache to disk. It creates parent directories if needed.
func (c *Cache) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create parent directory if it doesn't exist
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.FileOperationError(
			"Creating cache directory",
			dir,
			"Failed to create directory for cache file",
			err,
		)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return errors.ConfigError(
			"Serializing cache",
			"Failed to marshal cache to JSON",
			err,
		)
	}

	// Write atomically by writing to temp file then renaming
	tempPath := c.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return errors.FileOperationError(
			"Writing cache file",
			tempPath,
			"Failed to write temporary cache file",
			err,
		)
	}

	if err := os.Rename(tempPath, c.path); err != nil {
		// Clean up temp file on failure
		_ = os.Remove(tempPath)
		return errors.FileOperationError(
			"Saving cache file",
			c.path,
			"Failed to rename temporary cache file",
			err,
		)
	}

	return nil
}

// NeedsRefresh determines if a secret should be fetched from 1Password.
// It returns true (needs refresh) if:
//   - No cache entry exists for this path
//   - The reference has changed (secret rotated in config)
//   - The output file doesn't exist
//   - The output file's content doesn't match the cached hash
//   - The TTL has expired
func (c *Cache) NeedsRefresh(outputPath, reference string, ttl time.Duration) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.Entries[outputPath]
	if !exists {
		return true // Never cached
	}

	// Check if reference changed (config was updated)
	if entry.Reference != reference {
		return true
	}

	// Check if file exists and matches cached hash
	if !c.fileMatchesHash(outputPath, entry.ContentHash) {
		return true
	}

	// Check if TTL has expired
	if time.Since(entry.LastFetched) > ttl {
		return true
	}

	return false
}

// Update records a successfully fetched secret in the cache.
// The value parameter is the secret content (used to compute the hash).
func (c *Cache) Update(outputPath, reference, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Entries[outputPath] = Entry{
		Reference:   reference,
		ContentHash: computeHash(value),
		LastFetched: time.Now(),
	}
}

// Remove deletes a cache entry for the given path.
func (c *Cache) Remove(outputPath string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.Entries, outputPath)
}

// fileMatchesHash checks if a file exists and its content matches the expected hash.
func (c *Cache) fileMatchesHash(path, expectedHash string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false // File doesn't exist or can't be read
	}

	actualHash := computeHash(string(data))
	return actualHash == expectedHash
}

// computeHash returns the SHA256 hash of the given content as a hex string.
func computeHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// Size returns the number of entries in the cache.
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Entries)
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Entries = make(map[string]Entry)
}
