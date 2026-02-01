package libcage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type dumpItem struct {
	Name   string
	IsEnv  bool
	Bytes  []byte
	Source string
}

func (c *Cage) Dump(specs []string, out io.Writer) error {
	if len(specs) == 0 {
		return fmt.Errorf("dump: expected at least 1 argument")
	}

	var items []dumpItem
	var envCount, blobCount int

	for _, spec := range specs {
		if strings.HasPrefix(spec, "@") {
			envName := strings.TrimPrefix(spec, "@")
			if c.Root == "" || c.Cfg == nil {
				return fmt.Errorf("@env requires cage root")
			}
			env, ok := c.Cfg.Envs[envName]
			if !ok {
				return fmt.Errorf("unknown env %q", envName)
			}
			for _, fspec := range env.Files {
				ref, err := ParseSecretRef(fspec)
				if err != nil {
					return err
				}
				if !IsEnvSecretName(ref.Name) {
					c.Logger.Warn("dump: skipping blob in env", "env", envName, "secret", ref.String())
					continue
				}
				b, err := c.ReadSecretPlainPreferStore(ref)
				if err != nil {
					return err
				}
				items = append(items, dumpItem{Name: ref.Name, IsEnv: true, Bytes: b, Source: spec})
				envCount++
			}
			continue
		}

		if strings.HasSuffix(spec, ".cage") {
			item, err := c.dumpFromCageFile(spec)
			if err != nil {
				return err
			}
			items = append(items, item)
			if item.IsEnv {
				envCount++
			} else {
				blobCount++
			}
			continue
		}

		// Secret ref
		if c.Root == "" || c.Cfg == nil {
			return fmt.Errorf("secret ref %q requires cage root", spec)
		}
		ref, err := ParseSecretRef(spec)
		if err != nil {
			return err
		}
		b, err := c.ReadSecretPlainPreferStore(ref)
		if err != nil {
			return err
		}
		isEnv := IsEnvSecretName(ref.Name)
		items = append(items, dumpItem{Name: ref.Name, IsEnv: isEnv, Bytes: b, Source: spec})
		if isEnv {
			envCount++
		} else {
			blobCount++
		}
	}

	if envCount > 0 && blobCount > 0 {
		return fmt.Errorf("dump: cannot mix .env secrets and blobs")
	}
	if blobCount > 0 && len(items) > 1 {
		return fmt.Errorf("dump: blob can be dumped only as a single argument")
	}

	for _, it := range items {
		if _, err := out.Write(it.Bytes); err != nil {
			return err
		}
	}
	return nil
}

func (c *Cage) dumpFromCageFile(path string) (dumpItem, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return dumpItem{}, err
	}
	kind, err := ReadKind(b)
	if err != nil {
		return dumpItem{}, err
	}
	switch kind {
	case "secret/v1":
		s, err := ParseSecretV1(b)
		if err != nil {
			return dumpItem{}, err
		}
		if c.Ids.Empty() {
			return dumpItem{}, fmt.Errorf("dump %s: no identities", path)
		}
		cipher, err := DecodePayload(s.Secret.Payload)
		if err != nil {
			return dumpItem{}, err
		}
		plain, err := DecryptBytes(cipher, c.Ids.Age()...)
		if err != nil {
			return dumpItem{}, err
		}
		return dumpItem{Name: s.Secret.Name, IsEnv: IsEnvSecretName(s.Secret.Name), Bytes: plain, Source: path}, nil
	case "environment/v1":
		e, err := ParseEnvironmentV1(b)
		if err != nil {
			return dumpItem{}, err
		}
		if c.Ids.Empty() {
			return dumpItem{}, fmt.Errorf("dump %s: no identities", path)
		}
		// Dump of env file returns concatenated env secret contents; blobs are skipped.
		var merged []byte
		for _, s := range e.Environment.Secrets {
			name := s.Secret.Name
			if !IsEnvSecretName(name) {
				c.Logger.Warn("dump: skipping blob in environment file", "env_file", filepath.Base(path), "secret", name)
				continue
			}
			cipher, err := DecodePayload(s.Secret.Payload)
			if err != nil {
				return dumpItem{}, err
			}
			plain, err := DecryptBytes(cipher, c.Ids.Age()...)
			if err != nil {
				return dumpItem{}, err
			}
			merged = append(merged, plain...)
		}
		return dumpItem{Name: filepath.Base(path), IsEnv: true, Bytes: merged, Source: path}, nil
	default:
		return dumpItem{}, fmt.Errorf("dump %s: unsupported kind %q", path, kind)
	}
}
