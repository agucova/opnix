package systemd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/brizzbuzz/opnix/internal/config"
	"github.com/brizzbuzz/opnix/internal/errors"
	"github.com/brizzbuzz/opnix/internal/store"
)

// ServiceAction defines how to handle a service when secrets change
type ServiceAction struct {
	Name    string
	Restart bool
	Signal  string
	After   []string
}

// Manager handles systemd service integration and change detection
type Manager struct {
	config    config.SystemdIntegration
	store     *store.SecretStore
	dryRun    bool
	systemctl string
}

// NewManager creates a new systemd integration manager.
// The store parameter is used for change detection when enabled.
func NewManager(cfg config.SystemdIntegration, s *store.SecretStore) (*Manager, error) {
	// Find systemctl binary
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return nil, errors.FileOperationError(
			"Finding systemctl binary",
			"systemctl",
			"systemctl not found in PATH - systemd integration requires systemd",
			err,
		)
	}

	return &Manager{
		config:    cfg,
		store:     s,
		systemctl: systemctl,
	}, nil
}

// ExtractServiceActions extracts service actions from secret configuration
func (m *Manager) ExtractServiceActions(secret config.Secret, secretName string) ([]ServiceAction, error) {
	if secret.Services == nil {
		return nil, nil
	}

	var actions []ServiceAction

	switch services := secret.Services.(type) {
	case []interface{}:
		// Simple list of service names
		for _, svc := range services {
			if serviceName, ok := svc.(string); ok {
				actions = append(actions, ServiceAction{
					Name:    serviceName,
					Restart: m.config.RestartOnChange,
					After:   []string{"opnix-secrets.service"},
				})
			}
		}

	case map[string]interface{}:
		// Advanced service configuration
		for serviceName, svcConfig := range services {
			action := ServiceAction{
				Name:    serviceName,
				Restart: m.config.RestartOnChange,
				After:   []string{"opnix-secrets.service"},
			}

			// Parse service configuration
			if configMap, ok := svcConfig.(map[string]interface{}); ok {
				if restart, ok := configMap["restart"].(bool); ok {
					action.Restart = restart
				}
				if signal, ok := configMap["signal"].(string); ok {
					action.Signal = signal
				}
				if after, ok := configMap["after"].([]interface{}); ok {
					var afterServices []string
					for _, a := range after {
						if afterService, ok := a.(string); ok {
							afterServices = append(afterServices, afterService)
						}
					}
					action.After = afterServices
				}
			}

			actions = append(actions, action)
		}

	default:
		return nil, errors.ConfigError(
			fmt.Sprintf("Parsing services for secret %s", secretName),
			"Services field must be an array of strings or object with service configurations",
			nil,
		)
	}

	return actions, nil
}

// ProcessSecretChanges processes secrets and determines which services need restart
func (m *Manager) ProcessSecretChanges(secrets []config.Secret, secretPaths map[string]string) error {
	if !m.config.Enable {
		return nil
	}

	var changedSecrets []string
	var allServiceActions []ServiceAction

	// Check each secret for changes
	for i, secret := range secrets {
		secretName := fmt.Sprintf("secret[%d]:%s", i, secret.Path)

		// Get the actual file path for this secret
		var secretPath string
		if secret.Path != "" {
			if filepath.IsAbs(secret.Path) {
				secretPath = secret.Path
			} else {
				// This would need to be calculated based on the path resolution logic
				// For now, assume it's provided in secretPaths
				if path, exists := secretPaths[secretName]; exists {
					secretPath = path
				} else {
					continue // Skip if we can't determine the path
				}
			}
		}

		// Check if change detection is enabled
		hasChanged := true // Default to always changed if detection disabled
		if m.config.ChangeDetection.Enable && m.store != nil {
			var err error
			hasChanged, err = m.store.HasChanged(secretPath)
			if err != nil {
				if m.config.ErrorHandling.ContinueOnError {
					fmt.Fprintf(os.Stderr, "WARNING: Failed to check changes for %s: %v\n", secretName, err)
					continue
				}
				return err
			}
		}

		if hasChanged {
			changedSecrets = append(changedSecrets, secretName)

			// Extract service actions for this secret
			actions, err := m.ExtractServiceActions(secret, secretName)
			if err != nil {
				if m.config.ErrorHandling.ContinueOnError {
					fmt.Fprintf(os.Stderr, "WARNING: Failed to extract service actions for %s: %v\n", secretName, err)
					continue
				}
				return err
			}

			allServiceActions = append(allServiceActions, actions...)
		}
	}

	// Save store if we have changes and change detection is enabled
	if len(changedSecrets) > 0 && m.config.ChangeDetection.Enable && m.store != nil {
		if err := m.store.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Failed to save state: %v\n", err)
		}
	}

	// Process service actions if we have changes
	if len(allServiceActions) > 0 {
		fmt.Printf("INFO: Processing %d changed secrets: %v\n", len(changedSecrets), changedSecrets)
		return m.processServiceActions(allServiceActions)
	}

	fmt.Printf("INFO: No secret changes detected, skipping service restarts\n")
	return nil
}

// processServiceActions executes the required service actions
func (m *Manager) processServiceActions(actions []ServiceAction) error {
	// Group actions by service to avoid duplicate operations
	serviceActions := make(map[string]ServiceAction)
	for _, action := range actions {
		// If we already have an action for this service, prefer restart over reload
		if existing, exists := serviceActions[action.Name]; exists {
			if action.Restart && !existing.Restart {
				serviceActions[action.Name] = action
			}
		} else {
			serviceActions[action.Name] = action
		}
	}

	// Execute actions with retry logic
	var failures []string
	for serviceName, action := range serviceActions {
		if err := m.executeServiceAction(action); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", serviceName, err))

			if !m.config.ErrorHandling.ContinueOnError {
				return errors.ServiceError(
					fmt.Sprintf("Executing service action for %s", serviceName),
					serviceName,
					"restart/reload",
					err,
				)
			}
		}
	}

	if len(failures) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: Some service actions failed: %v\n", failures)
	}

	return nil
}

// executeServiceAction executes a single service action with retry logic
func (m *Manager) executeServiceAction(action ServiceAction) error {
	var cmd string
	var args []string

	if action.Signal != "" {
		// Send custom signal
		cmd = "kill"
		args = []string{"-" + action.Signal, fmt.Sprintf("$(systemctl show -p MainPID --value %s)", action.Name)}
		fmt.Printf("INFO: Sending %s signal to service %s\n", action.Signal, action.Name)
	} else if action.Restart {
		// Restart service
		cmd = m.systemctl
		args = []string{"restart", action.Name}
		fmt.Printf("INFO: Restarting service %s\n", action.Name)
	} else {
		// Reload service
		cmd = m.systemctl
		args = []string{"reload", action.Name}
		fmt.Printf("INFO: Reloading service %s\n", action.Name)
	}

	// Execute with retry logic
	var lastErr error
	for attempt := 0; attempt < m.config.ErrorHandling.MaxRetries; attempt++ {
		if attempt > 0 {
			fmt.Printf("INFO: Retrying service action for %s (attempt %d/%d)\n",
				action.Name, attempt+1, m.config.ErrorHandling.MaxRetries)
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		if m.dryRun {
			fmt.Printf("DRY-RUN: Would execute: %s %s\n", cmd, strings.Join(args, " "))
			return nil
		}

		execCmd := exec.Command(cmd, args...)
		output, err := execCmd.CombinedOutput()
		if err != nil {
			lastErr = fmt.Errorf("command failed: %v, output: %s", err, string(output))
			continue
		}

		// Success
		fmt.Printf("INFO: Successfully executed service action for %s\n", action.Name)
		return nil
	}

	return lastErr
}

// SetDryRun enables dry-run mode for testing
func (m *Manager) SetDryRun(dryRun bool) {
	m.dryRun = dryRun
}

// IsServiceRunning checks if a systemd service is currently running
func (m *Manager) IsServiceRunning(serviceName string) (bool, error) {
	cmd := exec.Command(m.systemctl, "is-active", "--quiet", serviceName)
	err := cmd.Run()

	if err == nil {
		return true, nil
	}

	// Check if it's an exit status error (service not running) vs other error
	if exitError, ok := err.(*exec.ExitError); ok {
		// systemctl is-active returns exit code 3 for inactive services
		if exitError.ExitCode() == 3 {
			return false, nil
		}
	}

	// Other error occurred
	return false, errors.ServiceError(
		"Checking service status",
		serviceName,
		"is-active",
		err,
	)
}

// ValidateServices checks that all configured services exist and are valid
func (m *Manager) ValidateServices(services []string) error {
	for _, serviceName := range services {
		// Check if service unit exists
		cmd := exec.Command(m.systemctl, "cat", serviceName)
		if err := cmd.Run(); err != nil {
			return errors.ServiceError(
				"Validating service configuration",
				serviceName,
				"cat",
				fmt.Errorf("service unit not found or not accessible"),
			)
		}
	}

	return nil
}
