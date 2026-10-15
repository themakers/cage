package libcage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// EnvVar — one variable of a built environment and the secret it came from.
type EnvVar struct {
	Name   string
	Value  string
	Source string // secret ref or file the variable came from
}

var prefixSpecRe = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=(.+)$`)

// splitPrefix parses "PREFIX_=spec": variables of spec get PREFIX_
// prepended. Specs without "=" have no prefix (refs and paths never
// contain "=").
func splitPrefix(spec string) (prefix, rest string) {
	if m := prefixSpecRe.FindStringSubmatch(spec); m != nil {
		return m[1], m[2]
	}
	return "", spec
}

// envCollector accumulates variables and rejects the same name coming from
// different secrets: the result of such a merge would depend on order (and,
// for dump, on the consumer's parser).
type envCollector struct {
	byName map[string]EnvVar
	order  []string
}

func newEnvCollector() *envCollector {
	return &envCollector{byName: map[string]EnvVar{}}
}

func (e *envCollector) add(prefix, source string, plain []byte) error {
	m, err := ParseDotenv(plain)
	if err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := prefix + k
		if prev, ok := e.byName[name]; ok && prev.Source != source {
			return fmt.Errorf("variable %s is defined by both %s and %s", name, prev.Source, source)
		}
		if _, ok := e.byName[name]; !ok {
			e.order = append(e.order, name)
		}
		e.byName[name] = EnvVar{Name: name, Value: m[k], Source: source}
	}
	return nil
}

func (e *envCollector) vars() []EnvVar {
	out := make([]EnvVar, 0, len(e.order))
	for _, n := range e.order {
		out = append(out, e.byName[n])
	}
	return out
}

// BuildEnvVars builds environment variables by decrypting/reading secrets.
// In non-raw mode, specs may contain secret refs (alias:name) and @env.
// In raw mode, specs must be *.cage paths or directories containing *.cage.
// Any spec may be prefixed: "PREFIX_=spec".
func (c *Cage) BuildEnvVars(specs []string, raw bool) (map[string]string, error) {
	vars, err := c.BuildEnv(specs, raw)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(vars))
	for _, v := range vars {
		out[v.Name] = v.Value
	}
	return out, nil
}

// BuildEnv is BuildEnvVars with the source of every variable.
func (c *Cage) BuildEnv(specs []string, raw bool) ([]EnvVar, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("run: at least one secret/@env is required")
	}
	col := newEnvCollector()

	if raw {
		if c.Ids.Empty() {
			return nil, fmt.Errorf("run -raw: no identities")
		}
		for _, spec := range specs {
			prefix, rest := splitPrefix(spec)
			paths, err := ExpandCageInputs([]string{rest})
			if err != nil {
				return nil, err
			}
			for _, p := range paths {
				if err := c.collectRawFile(col, prefix, p); err != nil {
					return nil, err
				}
			}
		}
		return col.vars(), nil
	}

	if c.Root == "" || c.Cfg == nil {
		return nil, fmt.Errorf("run: requires cage root")
	}
	type item struct {
		prefix string
		ref    SecretRef
	}
	var items []item
	seen := map[item]bool{}
	for _, spec := range specs {
		prefix, rest := splitPrefix(spec)
		refs, err := c.expandEnvSpec(rest)
		if err != nil {
			return nil, err
		}
		for _, ref := range refs {
			it := item{prefix, ref}
			if !seen[it] {
				seen[it] = true
				items = append(items, it)
			}
		}
	}
	for _, it := range items {
		plain, err := c.ReadSecretPlainPreferStore(it.ref)
		if err != nil {
			return nil, err
		}
		if err := col.add(it.prefix, it.ref.String(), plain); err != nil {
			return nil, err
		}
	}
	return col.vars(), nil
}

// expandEnvSpec resolves "@env" or a single .env secret ref.
func (c *Cage) expandEnvSpec(spec string) ([]SecretRef, error) {
	if strings.HasPrefix(spec, "@") {
		envName := strings.TrimPrefix(spec, "@")
		env, ok := c.Cfg.Envs[envName]
		if !ok {
			return nil, fmt.Errorf("unknown env %q", envName)
		}
		var out []SecretRef
		for _, fspec := range env.Files {
			ref, err := ParseSecretRef(fspec)
			if err != nil {
				return nil, err
			}
			if !IsEnvSecretName(ref.Name) {
				c.Logger.Debug("skipping blob in env", "env", envName, "secret", ref.String())
				continue
			}
			out = append(out, ref)
		}
		return out, nil
	}
	ref, err := ParseSecretRef(spec)
	if err != nil {
		return nil, err
	}
	if !IsEnvSecretName(ref.Name) {
		return nil, fmt.Errorf("%s is a blob secret; use dump/decrypt", ref.String())
	}
	return []SecretRef{ref}, nil
}

func (c *Cage) collectRawFile(col *envCollector, prefix, p string) error {
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
			return err
		}
		if !IsEnvSecretName(s.Secret.Name) {
			return fmt.Errorf("run -raw: %s is a blob secret (%s)", filepath.Base(p), s.Secret.Name)
		}
		plain, err := c.decryptSecret(s)
		if err != nil {
			return err
		}
		return col.add(prefix, s.Secret.Name, plain)
	case "environment/v1":
		e, err := ParseEnvironmentV1(b)
		if err != nil {
			return err
		}
		for _, s := range e.Environment.Secrets {
			if !IsEnvSecretName(s.Secret.Name) {
				c.Logger.Debug("run -raw: skipping blob in environment", "env_file", filepath.Base(p), "secret", s.Secret.Name)
				continue
			}
			plain, err := c.decryptSecret(&s)
			if err != nil {
				return err
			}
			if err := col.add(prefix, s.Secret.Name, plain); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("run -raw: unsupported kind %q in %s", kind, p)
	}
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
