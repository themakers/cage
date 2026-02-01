package libcage

import (
	"fmt"
	"os"
	"path/filepath"
)

const DefaultInitYAML = `kind: cage/v1

# dirs are non-recursive; paths are relative to cage root
# "default" is reserved and may be used without prefix

dirs:
  default: secrets

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
	return AtomicWriteFile(cfgPath, []byte(DefaultInitYAML), 0o600)
}
