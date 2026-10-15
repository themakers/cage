package libcage

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const DefaultInitYAML = `kind: cage/v1

# dirs are non-recursive; paths are relative to cage root and must be
# inside .cage/ (cage keeps .cage/.gitignore ignoring them).
# "default" is reserved and may be used without prefix

dirs:
  default: .cage/secrets

recipients: {}

envs: {}
`

func InitCage(root string) error {
	if root == "" {
		return fmt.Errorf("root is required")
	}
	cageDir := filepath.Join(root, ".cage")
	if err := EnsureDir(filepath.Join(cageDir, "store", "envs")); err != nil {
		return err
	}
	if err := EnsureDir(filepath.Join(cageDir, "store", "files", "default")); err != nil {
		return err
	}
	cfgPath := filepath.Join(cageDir, "cage.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		return fmt.Errorf("%s already exists", cfgPath)
	}
	if err := AtomicWriteFile(cfgPath, []byte(DefaultInitYAML), 0o600); err != nil {
		return err
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	return (&Cage{Root: root, Cfg: cfg, Logger: discardLogger()}).WriteGitignore()
}
