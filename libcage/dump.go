package libcage

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// dumpPart — one decrypted secret to output.
type dumpPart struct {
	Name   string
	IsEnv  bool
	Bytes  []byte
	Source string
	Prefix string
}

// Dump writes the specified secrets to out. Specs: secret refs, @env,
// explicit *.cage files; .env specs may be prefixed ("PREFIX_=spec").
// .env secrets are checked for variable collisions (the same name from
// different secrets is an error) and separated by newlines; prefixed ones
// are re-serialized with the prefix.
func (c *Cage) Dump(specs []string, out io.Writer) error {
	if len(specs) == 0 {
		return fmt.Errorf("dump: expected at least 1 argument")
	}

	var parts []dumpPart
	for _, spec := range specs {
		prefix, rest := splitPrefix(spec)
		got, err := c.dumpParts(rest)
		if err != nil {
			return err
		}
		for i := range got {
			got[i].Prefix = prefix
		}
		parts = append(parts, got...)
	}

	var envCount, blobCount int
	for _, p := range parts {
		if p.IsEnv {
			envCount++
		} else {
			blobCount++
			if p.Prefix != "" {
				return fmt.Errorf("dump: prefix is not applicable to blob %s", p.Source)
			}
		}
	}
	if envCount > 0 && blobCount > 0 {
		return fmt.Errorf("dump: cannot mix .env secrets and blobs")
	}
	if blobCount > 0 {
		if len(parts) > 1 {
			return fmt.Errorf("dump: blob can be dumped only as a single argument")
		}
		_, err := out.Write(parts[0].Bytes)
		return err
	}

	col := newEnvCollector()
	for _, p := range parts {
		if err := col.add(p.Prefix, p.Source, p.Bytes); err != nil {
			return fmt.Errorf("dump: %w", err)
		}
	}
	var buf bytes.Buffer
	for _, p := range parts {
		if p.Prefix == "" {
			buf.Write(p.Bytes)
			if len(p.Bytes) > 0 && p.Bytes[len(p.Bytes)-1] != '\n' {
				buf.WriteByte('\n')
			}
			continue
		}
		m, _ := ParseDotenv(p.Bytes)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			line, err := FormatDotenvLine(p.Prefix+k, m[k])
			if err != nil {
				return fmt.Errorf("dump %s: %w", p.Source, err)
			}
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	_, err := out.Write(buf.Bytes())
	return err
}

func (c *Cage) dumpParts(spec string) ([]dumpPart, error) {
	if strings.HasPrefix(spec, "@") {
		if c.Root == "" || c.Cfg == nil {
			return nil, fmt.Errorf("@env requires cage root")
		}
		refs, err := c.expandEnvSpec(spec)
		if err != nil {
			return nil, err
		}
		var out []dumpPart
		for _, ref := range refs {
			b, err := c.ReadSecretPlainPreferStore(ref)
			if err != nil {
				return nil, err
			}
			out = append(out, dumpPart{Name: ref.Name, IsEnv: true, Bytes: b, Source: ref.String()})
		}
		return out, nil
	}
	if strings.HasSuffix(spec, ".cage") {
		return c.dumpFromCageFile(spec)
	}
	if c.Root == "" || c.Cfg == nil {
		return nil, fmt.Errorf("secret ref %q requires cage root", spec)
	}
	ref, err := ParseSecretRef(spec)
	if err != nil {
		return nil, err
	}
	b, err := c.ReadSecretPlainPreferStore(ref)
	if err != nil {
		return nil, err
	}
	return []dumpPart{{Name: ref.Name, IsEnv: IsEnvSecretName(ref.Name), Bytes: b, Source: ref.String()}}, nil
}

func (c *Cage) dumpFromCageFile(path string) ([]dumpPart, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kind, err := ReadKind(b)
	if err != nil {
		return nil, err
	}
	if c.Ids.Empty() {
		return nil, fmt.Errorf("dump %s: no identities", path)
	}
	switch kind {
	case "secret/v1":
		s, err := ParseSecretV1(b)
		if err != nil {
			return nil, err
		}
		plain, err := c.decryptSecretPayload(s.Secret.Payload)
		if err != nil {
			return nil, err
		}
		return []dumpPart{{Name: s.Secret.Name, IsEnv: IsEnvSecretName(s.Secret.Name), Bytes: plain, Source: s.Secret.Name}}, nil
	case "environment/v1":
		e, err := ParseEnvironmentV1(b)
		if err != nil {
			return nil, err
		}
		var out []dumpPart
		for _, s := range e.Environment.Secrets {
			name := s.Secret.Name
			if !IsEnvSecretName(name) {
				c.Logger.Debug("dump: skipping blob in environment file", "env_file", filepath.Base(path), "secret", name)
				continue
			}
			plain, err := c.decryptSecretPayload(s.Secret.Payload)
			if err != nil {
				return nil, err
			}
			out = append(out, dumpPart{Name: name, IsEnv: true, Bytes: plain, Source: name})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("dump %s: unsupported kind %q", path, kind)
	}
}
