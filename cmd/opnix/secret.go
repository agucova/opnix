package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/brizzbuzz/opnix/internal/config"
	"github.com/brizzbuzz/opnix/internal/errors"
	"github.com/brizzbuzz/opnix/internal/onepass"
	"github.com/brizzbuzz/opnix/internal/secrets"
	"github.com/brizzbuzz/opnix/internal/store"
	"github.com/brizzbuzz/opnix/internal/systemd"
	"github.com/brizzbuzz/opnix/internal/validation"
)

const defaultTokenPath = "/etc/opnix-token"

type secretProcessor interface {
	Process(*config.Config) (*secrets.ProcessResult, error)
}

type systemdManager interface {
	ProcessSecretChanges([]config.Secret, map[string]string) error
}

type systemdManagerFactory func(config.SystemdIntegration, *store.SecretStore) (systemdManager, error)

type secretCommand struct {
	fs         *flag.FlagSet
	configFile string
	outputDir  string
	tokenFile  string
	force      bool // Force refresh all secrets, bypassing cache

	loadConfig       func(string) (*config.Config, error)
	newClient        func(string) (secrets.SecretClient, error)
	processorFactory func(secrets.SecretClient, string) secretProcessor
	systemdFactory   systemdManagerFactory
}

func newSecretCommand() *secretCommand {
	sc := &secretCommand{
		fs: flag.NewFlagSet("secret", flag.ExitOnError),
	}

	sc.fs.StringVar(&sc.configFile, "config", "secrets.json", "Path to secrets configuration file")
	sc.fs.StringVar(&sc.outputDir, "output", "secrets", "Directory to store retrieved secrets")
	sc.fs.StringVar(&sc.tokenFile, "token-file", defaultTokenPath, "Path to file containing 1Password service account token")
	sc.fs.BoolVar(&sc.force, "force", false, "Force refresh all secrets, bypassing cache")

	sc.fs.Usage = func() {
		fmt.Fprintf(sc.fs.Output(), "Usage: opnix secret [options]\n\n")
		fmt.Fprintf(sc.fs.Output(), "Retrieve and manage secrets from 1Password\n\n")
		fmt.Fprintf(sc.fs.Output(), "Options:\n")
		sc.fs.PrintDefaults()
	}

	sc.loadConfig = config.Load
	sc.newClient = func(path string) (secrets.SecretClient, error) {
		return onepass.NewClient(path)
	}
	sc.processorFactory = func(client secrets.SecretClient, outputDir string) secretProcessor {
		return secrets.NewProcessor(client, outputDir)
	}
	sc.systemdFactory = func(cfg config.SystemdIntegration, s *store.SecretStore) (systemdManager, error) {
		return systemd.NewManager(cfg, s)
	}

	return sc
}

func (s *secretCommand) Name() string { return s.fs.Name() }

func (s *secretCommand) Init(args []string) error {
	return s.fs.Parse(args)
}

func (s *secretCommand) Run() error {
	// Pre-flight checks
	if err := s.validatePrerequisites(); err != nil {
		return err
	}

	// Load configuration with improved error handling
	cfg, err := s.loadConfig(s.configFile)
	if err != nil {
		// Error already has context from config.Load
		return err
	}

	log.Printf("Loaded configuration with %d secrets", len(cfg.Secrets))

	// Initialize 1Password client with validation
	client, err := s.newClient(s.tokenFile)
	if err != nil {
		// Error already has context from onepass.NewClient
		return err
	}

	log.Printf("Initialized 1Password client successfully")

	// Create processor
	processor := s.processorFactory(client, s.outputDir)

	// Load unified state store for caching and change detection
	var secretStore *store.SecretStore
	stateFile := cfg.GetStateFile()

	// Load the store if caching is enabled or systemd change detection is enabled
	needsStore := (cfg.Caching.Enable && !s.force) || cfg.SystemdIntegration.ChangeDetection.Enable
	if needsStore {
		var err error
		secretStore, err = store.Load(stateFile)
		if err != nil {
			// Non-fatal: log warning and continue without store
			log.Printf("Warning: failed to load state, continuing without caching/change detection: %v", err)
		} else {
			log.Printf("State loaded from %s (%d entries)", stateFile, secretStore.Size())

			// Handle migration from legacy files if needed
			if cfg.Caching.CacheFile != "" || cfg.SystemdIntegration.ChangeDetection.HashFile != "" {
				if err := secretStore.MigrateFromCustomPaths(
					cfg.Caching.CacheFile,
					cfg.SystemdIntegration.ChangeDetection.HashFile,
				); err != nil {
					log.Printf("Warning: migration from legacy files failed: %v", err)
				}
			}
		}
	}

	// Set up caching if enabled and not forced
	if cfg.Caching.Enable && !s.force && secretStore != nil {
		ttl, err := time.ParseDuration(cfg.Caching.GetTTL())
		if err != nil {
			return errors.ConfigError(
				"Parsing cache TTL",
				fmt.Sprintf("Invalid TTL format '%s' - use Go duration format (e.g., 24h, 1h30m)", cfg.Caching.TTL),
				err,
			)
		}

		// Type assert to get the concrete processor type to call SetStore
		if p, ok := processor.(*secrets.Processor); ok {
			p.SetStore(secretStore, ttl)
			log.Printf("Caching enabled (TTL: %v, state file: %s)", ttl, stateFile)
		}
	} else if s.force {
		log.Printf("Force mode enabled - bypassing cache")
	}

	// Process secrets with detailed progress
	result, err := processor.Process(cfg)
	if err != nil {
		// Error already has context from processor.Process
		return err
	}

	if result.SkippedCount > 0 {
		log.Printf("Processed %d secrets (%d fetched, %d cached) to %s",
			result.ProcessedCount+result.SkippedCount, result.ProcessedCount, result.SkippedCount, s.outputDir)
	} else {
		log.Printf("Successfully processed %d secrets to %s", result.ProcessedCount, s.outputDir)
	}

	// Process systemd integration if enabled
	if cfg.SystemdIntegration.Enable {
		log.Printf("Processing systemd integration for %d services", len(cfg.SystemdIntegration.Services))

		systemdManager, err := s.systemdFactory(cfg.SystemdIntegration, secretStore)
		if err != nil {
			return errors.WrapWithSuggestions(
				err,
				"Initializing systemd integration",
				"systemd integration",
				[]string{
					"Ensure systemctl is available in PATH",
					"Check if running on a systemd-enabled system",
					"Consider disabling systemd integration if not needed",
				},
			)
		}

		if err := systemdManager.ProcessSecretChanges(cfg.Secrets, result.SecretPaths); err != nil {
			return errors.WrapWithSuggestions(
				err,
				"Processing systemd service changes",
				"systemd integration",
				[]string{
					"Check if specified services exist and are accessible",
					"Verify systemctl permissions",
					"Review systemd integration configuration",
					"Check systemd service logs: journalctl -u <service-name>",
				},
			)
		}

		log.Printf("Successfully processed systemd integration")
	}

	return nil
}

// validatePrerequisites performs pre-flight checks before processing
func (s *secretCommand) validatePrerequisites() error {
	// Check if config file exists
	if _, err := os.Stat(s.configFile); os.IsNotExist(err) {
		return errors.FileOperationError(
			"Checking configuration file",
			s.configFile,
			"Configuration file does not exist",
			err,
		)
	}

	// Check if output directory is writable
	if err := s.checkOutputDirectory(); err != nil {
		return err
	}

	// Validate token file (but don't fail if missing - let graceful handling work)
	validator := validation.NewValidator()
	if err := validator.ValidateTokenFile(s.tokenFile); err != nil {
		// For token errors, log a warning but don't fail
		fmt.Fprintf(os.Stderr, "WARNING: %v\n", err)
		fmt.Fprintf(os.Stderr, "INFO: Continuing with existing secrets if available\n")
	}

	return nil
}

// checkOutputDirectory ensures the output directory is accessible
func (s *secretCommand) checkOutputDirectory() error {
	// Try to create the directory if it doesn't exist
	if err := os.MkdirAll(s.outputDir, 0755); err != nil {
		return errors.FileOperationError(
			"Creating output directory",
			s.outputDir,
			"Cannot create or access output directory",
			err,
		)
	}

	// Test write permissions by creating a temporary file
	testFile := fmt.Sprintf("%s/.opnix-test", s.outputDir)
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return errors.FileOperationError(
			"Testing output directory permissions",
			s.outputDir,
			"Output directory is not writable",
			err,
		)
	}

	// Clean up test file
	_ = os.Remove(testFile) // Ignore error - cleanup is best effort

	return nil
}
