package libcage

import (
	"fmt"
	"path/filepath"
)

func (c *Cage) EnsureStoreDirs() error {
	if c.Root == "" || c.Cfg == nil {
		return fmt.Errorf("EnsureStoreDirs requires cage root + config")
	}
	if err := EnsureDir(filepath.Join(c.StoreDir(), "envs")); err != nil {
		return err
	}
	for alias := range c.Cfg.Dirs {
		if err := EnsureDir(filepath.Join(c.StoreDir(), "files", alias)); err != nil {
			return err
		}
	}
	return nil
}
