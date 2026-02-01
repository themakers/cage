package libcage

import (
	"fmt"
	"path/filepath"
	"strings"
)

func (c *Cage) CageDir() string {
	if c.Root == "" {
		return ""
	}
	return filepath.Join(c.Root, ".cage")
}

func (c *Cage) StoreDir() string {
	if c.Root == "" {
		return ""
	}
	return filepath.Join(c.CageDir(), "store")
}

func (c *Cage) ConfigPath() string {
	if c.Root == "" {
		return ""
	}
	return filepath.Join(c.CageDir(), "cage.yaml")
}

func (c *Cage) StoreSecretPath(ref SecretRef) (string, error) {
	if c.Root == "" {
		return "", fmt.Errorf("no cage root")
	}
	name := ref.Name
	if strings.ContainsAny(name, "/\\") {
		return "", fmt.Errorf("invalid secret name %q", name)
	}
	return filepath.Join(c.StoreDir(), "files", ref.Dir, name+".cage"), nil
}

func (c *Cage) StoreEnvPath(envName string) (string, error) {
	if c.Root == "" {
		return "", fmt.Errorf("no cage root")
	}
	if strings.ContainsAny(envName, "/\\") {
		return "", fmt.Errorf("invalid env name %q", envName)
	}
	return filepath.Join(c.StoreDir(), "envs", envName+".cage"), nil
}

func (c *Cage) PlaintextPath(ref SecretRef) (string, error) {
	if c.Root == "" || c.Cfg == nil {
		return "", fmt.Errorf("no cage root/config")
	}
	rel, ok := c.Cfg.Dirs[ref.Dir]
	if !ok {
		return "", fmt.Errorf("unknown dir alias %q", ref.Dir)
	}
	return filepath.Join(c.Root, filepath.FromSlash(rel), ref.Name), nil
}
