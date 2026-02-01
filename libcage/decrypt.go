package libcage

import (
	"fmt"
	"os"
	"path/filepath"
)

func (c *Cage) DecryptAll() error {
	if c.Root == "" || c.Cfg == nil {
		return fmt.Errorf("DecryptAll requires cage root + loaded config")
	}
	if c.Ids.Empty() {
		return fmt.Errorf("no usable identities; set CAGE_SSH_IDENTITY or ensure ~/.ssh private keys exist")
	}

	// Collect unique secrets referenced by envs.
	seen := map[SecretRef]bool{}
	for _, env := range c.Cfg.Envs {
		for _, fspec := range env.Files {
			ref, err := ParseSecretRef(fspec)
			if err != nil {
				return err
			}
			seen[ref] = true
		}
	}

	for ref := range seen {
		storePath, err := c.StoreSecretPath(ref)
		if err != nil {
			return err
		}
		b, ok, err := ReadFileIfExists(storePath)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("missing encrypted secret %s", storePath)
		}
		s, err := ParseSecretV1(b)
		if err != nil {
			return fmt.Errorf("parse %s: %w", storePath, err)
		}
		cipher, err := DecodePayload(s.Secret.Payload)
		if err != nil {
			return fmt.Errorf("decode payload %s: %w", storePath, err)
		}
		plain, err := DecryptBytes(cipher, c.Ids.Age()...)
		if err != nil {
			return fmt.Errorf("decrypt %s: %w", storePath, err)
		}
		outPath, err := c.PlaintextPath(ref)
		if err != nil {
			return err
		}
		if err := EnsureDir(filepath.Dir(outPath)); err != nil {
			return err
		}
		if err := os.WriteFile(outPath, plain, 0o600); err != nil {
			return err
		}
		c.Logger.Info("decrypted", "secret", ref.String(), "out", outPath)
	}
	return nil
}
