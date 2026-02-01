package libcage

import (
	"fmt"
	"os"
	"path/filepath"
)

type rawDecryptJob struct {
	Name    string
	Payload string
	Source  string
}

func (c *Cage) DecryptRaw(inputs []string, outDir string) error {
	if c.Ids.Empty() {
		return fmt.Errorf("no usable identities; set CAGE_SSH_IDENTITY or ensure ~/.ssh private keys exist")
	}
	paths, err := ExpandCageInputs(inputs)
	if err != nil {
		return err
	}
	if outDir == "" {
		return fmt.Errorf("-o is required in raw mode")
	}
	if err := EnsureDir(outDir); err != nil {
		return err
	}

	seen := map[string]string{}
	var jobs []rawDecryptJob

	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		kind, err := ReadKind(b)
		if err != nil {
			return fmt.Errorf("read kind %s: %w", p, err)
		}
		switch kind {
		case "secret/v1":
			s, err := ParseSecretV1(b)
			if err != nil {
				return fmt.Errorf("parse %s: %w", p, err)
			}
			name := s.Secret.Name
			if prev, ok := seen[name]; ok {
				return fmt.Errorf("output name collision for %q: %s and %s", name, prev, p)
			}
			seen[name] = p
			jobs = append(jobs, rawDecryptJob{Name: name, Payload: s.Secret.Payload, Source: p})
		case "environment/v1":
			e, err := ParseEnvironmentV1(b)
			if err != nil {
				return fmt.Errorf("parse %s: %w", p, err)
			}
			for _, s := range e.Environment.Secrets {
				name := s.Secret.Name
				if prev, ok := seen[name]; ok {
					return fmt.Errorf("output name collision for %q: %s and %s", name, prev, p)
				}
				seen[name] = p
				jobs = append(jobs, rawDecryptJob{Name: name, Payload: s.Secret.Payload, Source: p})
			}
		default:
			return fmt.Errorf("%s: unsupported kind %q", p, kind)
		}
	}

	for _, j := range jobs {
		cipher, err := DecodePayload(j.Payload)
		if err != nil {
			return fmt.Errorf("decode payload from %s: %w", j.Source, err)
		}
		plain, err := DecryptBytes(cipher, c.Ids.Age()...)
		if err != nil {
			return fmt.Errorf("decrypt %s (%s): %w", j.Source, j.Name, err)
		}
		outPath := filepath.Join(outDir, j.Name)
		if err := os.WriteFile(outPath, plain, 0o600); err != nil {
			return err
		}
	}

	return nil
}
