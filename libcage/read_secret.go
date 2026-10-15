package libcage

import (
	"fmt"
	"os"
)

// ReadSecretPlainPreferStore returns the content of a secret: the store
// version when it exists and identities are available, otherwise the
// plaintext file.
func (c *Cage) ReadSecretPlainPreferStore(ref SecretRef) ([]byte, error) {
	if c.Root != "" && !c.Ids.Empty() {
		s, err := c.readStoreVersion(ref)
		if err != nil {
			return nil, err
		}
		if s != nil {
			plain, err := c.decryptSecret(s.File)
			if err != nil {
				return nil, fmt.Errorf("decrypt %s: %w", ref, err)
			}
			return plain, nil
		}
	}

	// Fallback to plaintext file.
	if c.Root == "" || c.Cfg == nil {
		return nil, fmt.Errorf("no cage root/config for plaintext fallback")
	}
	p, err := c.PlaintextPath(ref)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read plaintext %s: %w", p, err)
	}
	return b, nil
}
