package libcage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BuildEnvVars builds environment variables by decrypting/reading secrets.
// In non-raw mode, specs may contain secret refs (alias:name) and @env.
// In raw mode, specs must be *.cage paths or directories containing *.cage.
func (c *Cage) BuildEnvVars(specs []string, raw bool) (map[string]string, error) {
	vars := map[string]string{}

	if raw {
		if c.Ids.Empty() {
			return nil, fmt.Errorf("run -raw: no identities")
		}
		paths, err := ExpandCageInputs(specs)
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			kind, err := ReadKind(b)
			if err != nil {
				return nil, fmt.Errorf("read kind %s: %w", p, err)
			}
			switch kind {
			case "secret/v1":
				s, err := ParseSecretV1(b)
				if err != nil {
					return nil, err
				}
				if !IsEnvSecretName(s.Secret.Name) {
					return nil, fmt.Errorf("run -raw: %s is a blob secret (%s)", filepath.Base(p), s.Secret.Name)
				}
				plain, err := c.decryptSecretPayload(s.Secret.Payload)
				if err != nil {
					return nil, err
				}
				m, err := ParseDotenv(plain)
				if err != nil {
					return nil, err
				}
				for k, v := range m {
					vars[k] = v
				}
			case "environment/v1":
				e, err := ParseEnvironmentV1(b)
				if err != nil {
					return nil, err
				}
				for _, s := range e.Environment.Secrets {
					name := s.Secret.Name
					if !IsEnvSecretName(name) {
						c.Logger.Warn("run -raw: skipping blob in environment", "env_file", filepath.Base(p), "secret", name)
						continue
					}
					plain, err := c.decryptSecretPayload(s.Secret.Payload)
					if err != nil {
						return nil, err
					}
					m, err := ParseDotenv(plain)
					if err != nil {
						return nil, err
					}
					for k, v := range m {
						vars[k] = v
					}
				}
			default:
				return nil, fmt.Errorf("run -raw: unsupported kind %q in %s", kind, p)
			}
		}
		return vars, nil
	}

	// Non-raw mode.
	if c.Root == "" || c.Cfg == nil {
		return nil, fmt.Errorf("run: requires cage root")
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("run: at least one secret/@env is required")
	}
	// Expand @env and secret refs in order.
	var refs []SecretRef
	seen := map[SecretRef]bool{}
	for _, spec := range specs {
		if strings.HasPrefix(spec, "@") {
			envName := strings.TrimPrefix(spec, "@")
			env, ok := c.Cfg.Envs[envName]
			if !ok {
				return nil, fmt.Errorf("unknown env %q", envName)
			}
			for _, fspec := range env.Files {
				ref, err := ParseSecretRef(fspec)
				if err != nil {
					return nil, err
				}
				if !IsEnvSecretName(ref.Name) {
					c.Logger.Warn("run: skipping blob in env", "env", envName, "secret", ref.String())
					continue
				}
				if !seen[ref] {
					refs = append(refs, ref)
					seen[ref] = true
				}
			}
			continue
		}
		ref, err := ParseSecretRef(spec)
		if err != nil {
			return nil, err
		}
		if !IsEnvSecretName(ref.Name) {
			return nil, fmt.Errorf("run: %s is a blob secret; use dump/decrypt", ref.String())
		}
		if !seen[ref] {
			refs = append(refs, ref)
			seen[ref] = true
		}
	}

	for _, ref := range refs {
		plain, err := c.ReadSecretPlainPreferStore(ref)
		if err != nil {
			return nil, err
		}
		m, err := ParseDotenv(plain)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ref.String(), err)
		}
		for k, v := range m {
			vars[k] = v
		}
	}
	return vars, nil
}

func (c *Cage) decryptSecretPayload(payload string) ([]byte, error) {
	cipher, err := DecodePayload(payload)
	if err != nil {
		return nil, err
	}
	plain, err := DecryptBytes(cipher, c.Ids.Age()...)
	if err != nil {
		return nil, err
	}
	return plain, nil
}
