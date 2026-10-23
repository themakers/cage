package main

import (
	"fmt"
	"log/slog"

	"github.com/themakers/cage/libcage"
)

// cage credentials prepare|clean <manifest.json> — the systemd credential
// preparer (see `cage skill infra`). It never prints values.
func cmdCredentials(logger *slog.Logger, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: cage credentials (prepare | clean) <manifest.json>")
	}
	if err := libcage.HardenCredentialsProcess(); err != nil {
		return err
	}
	m, err := libcage.LoadCredentialsManifest(args[1])
	if err != nil {
		return err
	}
	switch args[0] {
	case "prepare":
		//> A failed preparation must not leave the previous set to be loaded.
		if err := libcage.CleanCredentials(m); err != nil {
			return fmt.Errorf("unit %s: %w", m.Unit, err)
		}
		creds, err := libcage.ComposeCredentials(logger, m)
		if err != nil {
			return fmt.Errorf("unit %s: %w", m.Unit, err)
		}
		defer libcage.ClearCredentials(creds)
		if err := libcage.PublishCredentials(m, creds); err != nil {
			return fmt.Errorf("unit %s: %w", m.Unit, err)
		}
		names := make([]string, 0, len(m.Credentials))
		for _, c := range m.Credentials {
			names = append(names, c.Name)
		}
		logger.Info("credentials prepared", "unit", m.Unit, "credentials", names)
		return nil
	case "clean":
		if err := libcage.CleanCredentials(m); err != nil {
			return fmt.Errorf("unit %s: %w", m.Unit, err)
		}
		return nil
	default:
		return fmt.Errorf("credentials: unknown action %q (expected prepare or clean)", args[0])
	}
}
