package libcage

import (
	"fmt"
	"os"
)

func (c *Cage) ReadSecretPlainPreferStore(ref SecretRef) ([]byte, error) {
	// Prefer encrypted secret if available and we have identities.
	if c.Root != "" {
		storePath, err := c.StoreSecretPath(ref)
		if err == nil {
			b, ok, err := ReadFileIfExists(storePath)
			if err != nil {
				return nil, err
			}
			if ok && !c.Ids.Empty() {
				s, err := ParseSecretV1(b)
				if err != nil {
					return nil, fmt.Errorf("parse %s: %w", storePath, err)
				}
				cipher, err := DecodePayload(s.Secret.Payload)
				if err != nil {
					return nil, fmt.Errorf("decode payload %s: %w", storePath, err)
				}
				plain, err := DecryptBytes(cipher, c.Ids.Age()...)
				if err != nil {
					return nil, fmt.Errorf("decrypt %s: %w", storePath, err)
				}
				return plain, nil
			}
		}
	}

	// Fallback to plaintext file.
	if c.Root == "" || c.Cfg == nil {
		return nil, fmt.Errorf("no cage root/config for plaintext fallback")
	}
	plainPath, err := c.PlaintextPath(ref)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(plainPath)
	if err != nil {
		return nil, err
	}
	return b, nil
}
