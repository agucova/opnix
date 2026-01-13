package systemd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/brizzbuzz/opnix/internal/config"
	"github.com/brizzbuzz/opnix/internal/store"
)

// mockSystemdIntegration creates a test systemd integration config
func mockSystemdIntegration() config.SystemdIntegration {
	return config.SystemdIntegration{
		Enable:          true,
		Services:        []string{"caddy", "postgresql"},
		RestartOnChange: true,
		ChangeDetection: config.ChangeDetection{
			Enable: true,
		},
		ErrorHandling: config.ErrorHandling{
			RollbackOnFailure: false,
			ContinueOnError:   true,
			MaxRetries:        3,
		},
	}
}

func TestNewManager(t *testing.T) {
	// Test with systemctl available (most systems)
	cfg := mockSystemdIntegration()
	s := store.New("/tmp/test-state.json")
	manager, err := NewManager(cfg, s)

	if err != nil {
		// If systemctl is not available, skip this test
		t.Skipf("systemctl not available, skipping test: %v", err)
		return
	}

	if manager == nil {
		t.Fatal("Expected manager to be created, got nil")
	}

	if manager.config.Enable != cfg.Enable {
		t.Errorf("Expected Enable=%v, got %v", cfg.Enable, manager.config.Enable)
	}

	if len(manager.config.Services) != len(cfg.Services) {
		t.Errorf("Expected %d services, got %d", len(cfg.Services), len(manager.config.Services))
	}
}

func TestStoreChangeDetection(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "test-state.json")
	testFile := filepath.Join(tempDir, "test-secret.txt")

	// Create test file
	content1 := "secret-content-v1"
	if err := os.WriteFile(testFile, []byte(content1), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	s, err := store.Load(stateFile)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// First check - should detect change (new file)
	changed, err := s.HasChanged(testFile)
	if err != nil {
		t.Fatalf("Failed to check for changes: %v", err)
	}

	if !changed {
		t.Error("Expected change to be detected for new file")
	}

	// Second check with same content - should not detect change
	changed, err = s.HasChanged(testFile)
	if err != nil {
		t.Fatalf("Failed to check for changes: %v", err)
	}

	if changed {
		t.Error("Expected no change to be detected for same content")
	}

	// Modify file content
	content2 := "secret-content-v2"
	if err := os.WriteFile(testFile, []byte(content2), 0600); err != nil {
		t.Fatalf("Failed to update test file: %v", err)
	}

	// Should detect change
	changed, err = s.HasChanged(testFile)
	if err != nil {
		t.Fatalf("Failed to check for changes: %v", err)
	}

	if !changed {
		t.Error("Expected change to be detected for modified content")
	}
}

func TestExtractServiceActions(t *testing.T) {
	cfg := mockSystemdIntegration()
	manager := &Manager{config: cfg}

	tests := []struct {
		name          string
		secret        config.Secret
		expectedCount int
		expectedNames []string
		expectError   bool
	}{
		{
			name: "simple service list",
			secret: config.Secret{
				Path:      "test/secret",
				Reference: "op://vault/item/field",
				Services:  []interface{}{"caddy", "nginx"},
			},
			expectedCount: 2,
			expectedNames: []string{"caddy", "nginx"},
			expectError:   false,
		},
		{
			name: "advanced service config",
			secret: config.Secret{
				Path:      "test/secret",
				Reference: "op://vault/item/field",
				Services: map[string]interface{}{
					"postgresql": map[string]interface{}{
						"restart": true,
						"after":   []interface{}{"opnix-secrets.service"},
					},
					"backup-service": map[string]interface{}{
						"restart": false,
						"signal":  "SIGHUP",
					},
				},
			},
			expectedCount: 2,
			expectedNames: []string{"postgresql", "backup-service"},
			expectError:   false,
		},
		{
			name: "no services",
			secret: config.Secret{
				Path:      "test/secret",
				Reference: "op://vault/item/field",
				Services:  nil,
			},
			expectedCount: 0,
			expectedNames: []string{},
			expectError:   false,
		},
		{
			name: "invalid services type",
			secret: config.Secret{
				Path:      "test/secret",
				Reference: "op://vault/item/field",
				Services:  "invalid-type",
			},
			expectedCount: 0,
			expectedNames: []string{},
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actions, err := manager.ExtractServiceActions(tt.secret, "test-secret")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(actions) != tt.expectedCount {
				t.Errorf("Expected %d actions, got %d", tt.expectedCount, len(actions))
			}

			// Check that all expected service names are present
			actionNames := make(map[string]bool)
			for _, action := range actions {
				actionNames[action.Name] = true
			}

			for _, expectedName := range tt.expectedNames {
				if !actionNames[expectedName] {
					t.Errorf("Expected service %s not found in actions", expectedName)
				}
			}
		})
	}
}

func TestServiceActionConfiguration(t *testing.T) {
	cfg := mockSystemdIntegration()
	manager := &Manager{config: cfg}

	secret := config.Secret{
		Path:      "test/secret",
		Reference: "op://vault/item/field",
		Services: map[string]interface{}{
			"postgresql": map[string]interface{}{
				"restart": true,
				"after":   []interface{}{"opnix-secrets.service", "network.target"},
			},
			"backup-service": map[string]interface{}{
				"restart": false,
				"signal":  "SIGHUP",
			},
		},
	}

	actions, err := manager.ExtractServiceActions(secret, "test-secret")
	if err != nil {
		t.Fatalf("Failed to extract service actions: %v", err)
	}

	if len(actions) != 2 {
		t.Fatalf("Expected 2 actions, got %d", len(actions))
	}

	// Find postgresql action
	var pgAction *ServiceAction
	var backupAction *ServiceAction

	for i := range actions {
		switch actions[i].Name {
		case "postgresql":
			pgAction = &actions[i]
		case "backup-service":
			backupAction = &actions[i]
		}
	}

	if pgAction == nil {
		t.Fatal("postgresql action not found")
	}

	if !pgAction.Restart {
		t.Error("Expected postgresql to have restart=true")
	}

	if len(pgAction.After) != 2 {
		t.Errorf("Expected postgresql to have 2 dependencies, got %d", len(pgAction.After))
	}

	if backupAction == nil {
		t.Fatal("backup-service action not found")
	}

	if backupAction.Restart {
		t.Error("Expected backup-service to have restart=false")
	}

	if backupAction.Signal != "SIGHUP" {
		t.Errorf("Expected backup-service signal=SIGHUP, got %s", backupAction.Signal)
	}
}

func TestManagerDryRun(t *testing.T) {
	cfg := mockSystemdIntegration()
	s := store.New("/tmp/test-state.json")
	manager, err := NewManager(cfg, s)
	if err != nil {
		t.Skipf("systemctl not available, skipping test: %v", err)
		return
	}

	// Enable dry run
	manager.SetDryRun(true)

	action := ServiceAction{
		Name:    "test-service",
		Restart: true,
	}

	// Should not fail in dry run mode even if service doesn't exist
	err = manager.executeServiceAction(action)
	if err != nil {
		t.Errorf("Expected no error in dry run mode, got: %v", err)
	}
}

func TestProcessSecretChanges(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "test-state.json")

	cfg := config.SystemdIntegration{
		Enable:          true,
		RestartOnChange: true,
		ChangeDetection: config.ChangeDetection{
			Enable: true,
		},
		ErrorHandling: config.ErrorHandling{
			ContinueOnError: true,
			MaxRetries:      1,
		},
	}

	s, err := store.Load(stateFile)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	manager, err := NewManager(cfg, s)
	if err != nil {
		t.Skipf("systemctl not available, skipping test: %v", err)
		return
	}

	// Enable dry run to avoid actual systemctl calls
	manager.SetDryRun(true)

	// Create test secret file
	testSecretPath := filepath.Join(tempDir, "test-secret.txt")
	if err := os.WriteFile(testSecretPath, []byte("secret-content"), 0600); err != nil {
		t.Fatalf("Failed to create test secret: %v", err)
	}

	secrets := []config.Secret{
		{
			Path:      "test/secret",
			Reference: "op://vault/item/field",
			Services:  []interface{}{"test-service"},
		},
	}

	secretPaths := map[string]string{
		"secret[0]:test/secret": testSecretPath,
	}

	// Process changes - should not fail in dry run
	err = manager.ProcessSecretChanges(secrets, secretPaths)
	if err != nil {
		t.Errorf("ProcessSecretChanges failed: %v", err)
	}

	// Save the store and check that state file was created
	if err := s.Save(); err != nil {
		t.Fatalf("Failed to save store: %v", err)
	}

	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Error("Expected state file to be created")
	}
}

func TestStoreFileOperations(t *testing.T) {
	tempDir := t.TempDir()
	stateFile := filepath.Join(tempDir, "nested", "dir", "state.json")

	// Should create nested directories when saving
	s := store.New(stateFile)
	s.RecordFetch("/test", "op://vault/item", "value")

	if err := s.Save(); err != nil {
		t.Fatalf("Failed to save store with nested path: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(stateFile); os.IsNotExist(err) {
		t.Error("State file was not created")
	}

	// Load and verify
	loaded, err := store.Load(stateFile)
	if err != nil {
		t.Fatalf("Failed to load store: %v", err)
	}

	if loaded.Size() != 1 {
		t.Errorf("Expected 1 entry, got %d", loaded.Size())
	}
}

func TestComputeFileHash(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test-file.txt")

	// Create test file
	content := "test content for hashing"
	if err := os.WriteFile(testFile, []byte(content), 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Calculate hash
	hash1, err := store.ComputeFileHash(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate hash: %v", err)
	}

	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}

	// Calculate hash again - should be the same
	hash2, err := store.ComputeFileHash(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate hash second time: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Expected same hash, got %s and %s", hash1, hash2)
	}

	// Modify file and calculate hash - should be different
	if err := os.WriteFile(testFile, []byte(content+" modified"), 0600); err != nil {
		t.Fatalf("Failed to modify test file: %v", err)
	}

	hash3, err := store.ComputeFileHash(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate hash after modification: %v", err)
	}

	if hash1 == hash3 {
		t.Error("Expected different hash after file modification")
	}
}
