package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	s := New("/tmp/test-state.json")
	if s == nil {
		t.Fatal("Expected non-nil store")
	}
	if s.Entries == nil {
		t.Fatal("Expected non-nil entries map")
	}
	if len(s.Entries) != 0 {
		t.Errorf("Expected empty entries, got %d", len(s.Entries))
	}
	if s.Path() != "/tmp/test-state.json" {
		t.Errorf("Expected path /tmp/test-state.json, got %s", s.Path())
	}
}

func TestLoadNonExistent(t *testing.T) {
	s, err := Load("/tmp/nonexistent-state-12345.json")
	if err != nil {
		t.Fatalf("Expected no error for nonexistent file, got %v", err)
	}
	if s == nil {
		t.Fatal("Expected non-nil store")
	}
	if len(s.Entries) != 0 {
		t.Errorf("Expected empty entries for nonexistent file, got %d", len(s.Entries))
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// Create and save a store
	s := New(statePath)
	s.RecordFetch("/run/secrets/test", "op://Vault/Item/field", "secret-value")

	if err := s.Save(); err != nil {
		t.Fatalf("Failed to save store: %v", err)
	}

	// Load the store back
	loaded, err := Load(statePath)
	if err != nil {
		t.Fatalf("Failed to load store: %v", err)
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

func TestNeedsFetch_NoEntry(t *testing.T) {
	s := New("/tmp/test.json")
	if !s.NeedsFetch("/run/secrets/new", "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsFetch=true for missing entry")
	}
}

func TestNeedsFetch_ReferenceChanged(t *testing.T) {
	s := New("/tmp/test.json")
	s.RecordFetch("/run/secrets/test", "op://Vault/Item/old", "value")

	if !s.NeedsFetch("/run/secrets/test", "op://Vault/Item/new", 24*time.Hour) {
		t.Error("Expected NeedsFetch=true when reference changed")
	}
}

func TestNeedsFetch_TTLExpired(t *testing.T) {
	s := New("/tmp/test.json")

	// Create temp file
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")
	if err := os.WriteFile(secretPath, []byte("value"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Set entry with old timestamp
	s.Entries[secretPath] = SecretEntry{
		Reference:   "op://Vault/Item/field",
		ContentHash: ComputeHash("value"),
		LastFetched: time.Now().Add(-25 * time.Hour), // 25 hours ago
	}

	if !s.NeedsFetch(secretPath, "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsFetch=true when TTL expired")
	}
}

func TestNeedsFetch_FileMissing(t *testing.T) {
	s := New("/tmp/test.json")
	s.Entries["/run/secrets/missing"] = SecretEntry{
		Reference:   "op://Vault/Item/field",
		ContentHash: ComputeHash("value"),
		LastFetched: time.Now(),
	}

	if !s.NeedsFetch("/run/secrets/missing", "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsFetch=true when file is missing")
	}
}

func TestNeedsFetch_HashMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")

	// Write a different value than stored
	if err := os.WriteFile(secretPath, []byte("different"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	s := New("/tmp/test.json")
	s.Entries[secretPath] = SecretEntry{
		Reference:   "op://Vault/Item/field",
		ContentHash: ComputeHash("original"),
		LastFetched: time.Now(),
	}

	if !s.NeedsFetch(secretPath, "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsFetch=true when hash mismatches")
	}
}

func TestNeedsFetch_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")

	// Write the expected value
	if err := os.WriteFile(secretPath, []byte("secret-value"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	s := New("/tmp/test.json")
	s.Entries[secretPath] = SecretEntry{
		Reference:   "op://Vault/Item/field",
		ContentHash: ComputeHash("secret-value"),
		LastFetched: time.Now(),
	}

	if s.NeedsFetch(secretPath, "op://Vault/Item/field", 24*time.Hour) {
		t.Error("Expected NeedsFetch=false for valid entry")
	}
}

func TestHasChanged_NoEntry(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")
	if err := os.WriteFile(secretPath, []byte("value"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	s := New("/tmp/test.json")
	changed, err := s.HasChanged(secretPath)
	if err != nil {
		t.Fatalf("HasChanged failed: %v", err)
	}
	if !changed {
		t.Error("Expected HasChanged=true for new entry")
	}

	// Should now have the entry recorded
	if _, exists := s.Entries[secretPath]; !exists {
		t.Error("Expected entry to be recorded after HasChanged")
	}
}

func TestHasChanged_NoChange(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")
	if err := os.WriteFile(secretPath, []byte("value"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	s := New("/tmp/test.json")
	s.Entries[secretPath] = SecretEntry{
		ContentHash: ComputeHash("value"),
		LastFetched: time.Now(),
	}

	changed, err := s.HasChanged(secretPath)
	if err != nil {
		t.Fatalf("HasChanged failed: %v", err)
	}
	if changed {
		t.Error("Expected HasChanged=false when content unchanged")
	}
}

func TestHasChanged_ContentChanged(t *testing.T) {
	tmpDir := t.TempDir()
	secretPath := filepath.Join(tmpDir, "test")
	if err := os.WriteFile(secretPath, []byte("new-value"), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	s := New("/tmp/test.json")
	s.Entries[secretPath] = SecretEntry{
		ContentHash: ComputeHash("old-value"),
		LastFetched: time.Now().Add(-time.Hour),
	}

	changed, err := s.HasChanged(secretPath)
	if err != nil {
		t.Fatalf("HasChanged failed: %v", err)
	}
	if !changed {
		t.Error("Expected HasChanged=true when content changed")
	}

	// Hash should be updated
	if s.Entries[secretPath].ContentHash != ComputeHash("new-value") {
		t.Error("Expected hash to be updated after change detected")
	}
}

func TestComputeHash(t *testing.T) {
	hash1 := ComputeHash("hello")
	hash2 := ComputeHash("hello")
	hash3 := ComputeHash("world")

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

func TestComputeFileHash(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test")
	content := "test content for hashing"
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	hash, err := ComputeFileHash(filePath)
	if err != nil {
		t.Fatalf("ComputeFileHash failed: %v", err)
	}

	expectedHash := ComputeHash(content)
	if hash != expectedHash {
		t.Errorf("Expected hash %s, got %s", expectedHash, hash)
	}
}

func TestSize(t *testing.T) {
	s := New("/tmp/test.json")
	if s.Size() != 0 {
		t.Errorf("Expected size 0, got %d", s.Size())
	}

	s.RecordFetch("/path1", "ref1", "value1")
	s.RecordFetch("/path2", "ref2", "value2")
	if s.Size() != 2 {
		t.Errorf("Expected size 2, got %d", s.Size())
	}
}

func TestClear(t *testing.T) {
	s := New("/tmp/test.json")
	s.RecordFetch("/path1", "ref1", "value1")
	s.RecordFetch("/path2", "ref2", "value2")

	s.Clear()
	if s.Size() != 0 {
		t.Errorf("Expected size 0 after clear, got %d", s.Size())
	}
}

func TestRemove(t *testing.T) {
	s := New("/tmp/test.json")
	s.RecordFetch("/path1", "ref1", "value1")
	s.RecordFetch("/path2", "ref2", "value2")

	s.Remove("/path1")
	if s.Size() != 1 {
		t.Errorf("Expected size 1 after remove, got %d", s.Size())
	}
	if _, ok := s.Entries["/path1"]; ok {
		t.Error("Expected /path1 to be removed")
	}
}

func TestGetEntry(t *testing.T) {
	s := New("/tmp/test.json")
	s.RecordFetch("/path1", "ref1", "value1")

	entry, exists := s.GetEntry("/path1")
	if !exists {
		t.Error("Expected entry to exist")
	}
	if entry.Reference != "ref1" {
		t.Errorf("Expected reference ref1, got %s", entry.Reference)
	}

	_, exists = s.GetEntry("/nonexistent")
	if exists {
		t.Error("Expected nonexistent entry to not exist")
	}
}

func TestLoadCorrupted(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	// Write corrupted JSON
	if err := os.WriteFile(statePath, []byte("not valid json"), 0644); err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	s, err := Load(statePath)
	if err != nil {
		t.Fatalf("Expected no error for corrupted file (graceful recovery), got %v", err)
	}
	if s == nil {
		t.Fatal("Expected non-nil store for corrupted file")
	}
	if len(s.Entries) != 0 {
		t.Errorf("Expected empty entries for corrupted file, got %d", len(s.Entries))
	}
}

func TestAtomicSave(t *testing.T) {
	tmpDir := t.TempDir()

	// Save should work even if directory doesn't exist yet
	nestedPath := filepath.Join(tmpDir, "nested", "dir", "state.json")
	s := New(nestedPath)
	s.RecordFetch("/test", "ref", "value")

	if err := s.Save(); err != nil {
		t.Fatalf("Failed to save to nested path: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(nestedPath); os.IsNotExist(err) {
		t.Error("Expected state file to be created at nested path")
	}
}

func TestMigrateFromLegacyHashStore(t *testing.T) {
	tmpDir := t.TempDir()
	hashStorePath := filepath.Join(tmpDir, "hashes.json")
	statePath := filepath.Join(tmpDir, "state.json")

	// Create legacy hash store file
	legacyData := legacyHashStore{
		Hashes: map[string]legacySecretHash{
			"/run/secrets/api-key": {
				Path:         "/run/secrets/api-key",
				Hash:         "def456",
				LastModified: time.Now().Add(-time.Hour),
			},
		},
	}
	data, _ := json.Marshal(legacyData)
	if err := os.WriteFile(hashStorePath, data, 0644); err != nil {
		t.Fatalf("Failed to write legacy hash store: %v", err)
	}

	s := New(statePath)
	if err := s.migrateFromLegacyHashStore(hashStorePath); err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	if len(s.Entries) != 1 {
		t.Errorf("Expected 1 entry after migration, got %d", len(s.Entries))
	}

	entry, exists := s.Entries["/run/secrets/api-key"]
	if !exists {
		t.Fatal("Expected migrated entry")
	}
	if entry.ContentHash != "def456" {
		t.Errorf("Expected hash def456, got %s", entry.ContentHash)
	}
}

func TestMigrateFromCustomHashStorePath(t *testing.T) {
	tmpDir := t.TempDir()
	hashStorePath := filepath.Join(tmpDir, "custom-hashes.json")
	statePath := filepath.Join(tmpDir, "state.json")

	// Create custom hash store (upstream's format)
	hashData := legacyHashStore{
		Hashes: map[string]legacySecretHash{
			"/run/secrets/test": {
				Path:         "/run/secrets/test",
				Hash:         "testhash",
				LastModified: time.Now(),
			},
		},
	}
	data, _ := json.Marshal(hashData)
	os.WriteFile(hashStorePath, data, 0644)

	s := New(statePath)
	if err := s.MigrateFromCustomHashStorePath(hashStorePath); err != nil {
		t.Fatalf("MigrateFromCustomHashStorePath failed: %v", err)
	}

	if len(s.Entries) != 1 {
		t.Errorf("Expected 1 entry after migration, got %d", len(s.Entries))
	}

	// Check that hash store file was deleted
	if _, err := os.Stat(hashStorePath); !os.IsNotExist(err) {
		t.Error("Expected hash store file to be deleted after migration")
	}
}

func TestString(t *testing.T) {
	s := New("/tmp/test.json")
	s.RecordFetch("/path1", "ref1", "value1")

	str := s.String()
	if str == "" {
		t.Error("Expected non-empty string representation")
	}
	if !contains(str, "entries=1") {
		t.Errorf("Expected string to contain 'entries=1', got %s", str)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
