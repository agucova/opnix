package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	c := New("/tmp/test-cache.json")
	if c == nil {
		t.Fatal("Expected non-nil cache")
	}
	if c.Entries == nil {
		t.Fatal("Expected non-nil entries map")
	}
	if len(c.Entries) != 0 {
		t.Errorf("Expected empty entries, got %d", len(c.Entries))
	}
}

func TestLoadNonExistentCache(t *testing.T) {
	c, err := Load("/tmp/nonexistent-cache-12345.json")
	if err != nil {
		t.Fatalf("Expected no error for nonexistent file, got %v", err)
	}
	if c == nil {
		t.Fatal("Expected non-nil cache")
	}
	if len(c.Entries) != 0 {
		t.Errorf("Expected empty entries for nonexistent file, got %d", len(c.Entries))
	}
}

func TestSaveAndLoadCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	// Create and save a cache
	c := New(cachePath)
	c.Update("/run/secrets/test", "op://Vault/Item/field", "secret-value")

	if err := c.Save(); err != nil {
		t.Fatalf("Failed to save cache: %v", err)
	}

	// Load the cache back
	loaded, err := Load(cachePath)
	if err != nil {
		t.Fatalf("Failed to load cache: %v", err)
	}

	if len(loaded.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(loaded.Entries))
	}

	entry, ok := loaded.Entries["/run/secrets/test"]
	if !ok {
		t.Fatal("Expected entry for /run/secrets/test")
	}
	if entry.Reference != "op://Vault/Item/field" {
		t.Errorf("Expected reference op://Vault/Item/field, got %s", entry.Reference)
	}
}

func TestNeedsRefresh_NoEntry(t *testing.T) {
	c := New("/tmp/test.json")
	if !c.NeedsRefresh("/run/secrets/new", "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsRefresh=true for missing entry")
	}
}

func TestNeedsRefresh_ReferenceChanged(t *testing.T) {
	c := New("/tmp/test.json")
	c.Update("/run/secrets/test", "op://Vault/Item/old", "value")

	if !c.NeedsRefresh("/run/secrets/test", "op://Vault/Item/new", 24*time.Hour) {
		t.Error("Expected NeedsRefresh=true when reference changed")
	}
}

func TestNeedsRefresh_TTLExpired(t *testing.T) {
	c := New("/tmp/test.json")
	c.Entries["/run/secrets/test"] = Entry{
		Reference:   "op://Vault/Item/field",
		ContentHash: computeHash("value"),
		LastFetched: time.Now().Add(-25 * time.Hour), // 25 hours ago
	}

	// Create the file so hash check passes
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")
	if err := os.WriteFile(secretPath, []byte("value"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	c.Entries[secretPath] = c.Entries["/run/secrets/test"]
	delete(c.Entries, "/run/secrets/test")

	if !c.NeedsRefresh(secretPath, "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsRefresh=true when TTL expired")
	}
}

func TestNeedsRefresh_FileMissing(t *testing.T) {
	c := New("/tmp/test.json")
	c.Entries["/run/secrets/missing"] = Entry{
		Reference:   "op://Vault/Item/field",
		ContentHash: computeHash("value"),
		LastFetched: time.Now(),
	}

	if !c.NeedsRefresh("/run/secrets/missing", "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsRefresh=true when file is missing")
	}
}

func TestNeedsRefresh_HashMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")

	// Write a different value than cached
	if err := os.WriteFile(secretPath, []byte("different"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	c := New("/tmp/test.json")
	c.Entries[secretPath] = Entry{
		Reference:   "op://Vault/Item/field",
		ContentHash: computeHash("original"),
		LastFetched: time.Now(),
	}

	if !c.NeedsRefresh(secretPath, "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsRefresh=true when hash mismatches")
	}
}

func TestNeedsRefresh_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")

	// Write the expected value
	if err := os.WriteFile(secretPath, []byte("secret-value"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	c := New("/tmp/test.json")
	c.Entries[secretPath] = Entry{
		Reference:   "op://Vault/Item/field",
		ContentHash: computeHash("secret-value"),
		LastFetched: time.Now(),
	}

	if c.NeedsRefresh(secretPath, "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsRefresh=false for valid cached entry")
	}
}

func TestComputeHash(t *testing.T) {
	hash1 := computeHash("hello")
	hash2 := computeHash("hello")
	hash3 := computeHash("world")

	if hash1 != hash2 {
		t.Error("Same content should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("Different content should produce different hash")
	}
	if len(hash1) != 64 {
		t.Errorf("Expected 64-char hex hash, got %d chars", len(hash1))
	}
}

func TestCacheSize(t *testing.T) {
	c := New("/tmp/test.json")
	if c.Size() != 0 {
		t.Errorf("Expected size 0, got %d", c.Size())
	}

	c.Update("/path1", "ref1", "value1")
	c.Update("/path2", "ref2", "value2")
	if c.Size() != 2 {
		t.Errorf("Expected size 2, got %d", c.Size())
	}
}

func TestCacheClear(t *testing.T) {
	c := New("/tmp/test.json")
	c.Update("/path1", "ref1", "value1")
	c.Update("/path2", "ref2", "value2")

	c.Clear()
	if c.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", c.Size())
	}
}

func TestCacheRemove(t *testing.T) {
	c := New("/tmp/test.json")
	c.Update("/path1", "ref1", "value1")
	c.Update("/path2", "ref2", "value2")

	c.Remove("/path1")
	if c.Size() != 1 {
		t.Errorf("Expected size 1 after remove, got %d", c.Size())
	}
	if _, ok := c.Entries["/path1"]; ok {
		t.Error("Expected /path1 to be removed")
	}
}

func TestLoadCorruptedCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	// Write corrupted JSON
	if err := os.WriteFile(cachePath, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to write corrupted cache: %v", err)
	}

	c, err := Load(cachePath)
	if err != nil {
		t.Fatalf("Expected no error for corrupted file (graceful recovery), got %v", err)
	}
	if c == nil {
		t.Fatal("Expected non-nil cache for corrupted file")
	}
	if len(c.Entries) != 0 {
		t.Errorf("Expected empty entries for corrupted file, got %d", len(c.Entries))
	}
}

func TestAtomicSave(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "cache.json")

	c := New(cachePath)
	c.Update("/test", "ref", "value")

	// Save should work even if directory doesn't exist yet
	nestedPath := filepath.Join(tmpDir, "nested", "dir", "cache.json")
	c2 := New(nestedPath)
	c2.Update("/test", "ref", "value")

	if err := c2.Save(); err != nil {
		t.Fatalf("Failed to save to nested path: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		t.Error("Expected cache file to be created at nested path")
	}
}
