package libcage

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
)

func (c *Cage) EncryptAll() error {
	if c.Root == "" || c.Cfg == nil {
		return fmt.Errorf("EncryptAll requires cage root + loaded config")
	}
	if err := c.EnsureStoreDirs(); err != nil {
		return err
	}

	// Warn about .gitignore in each configured plaintext directory.
	for alias, rel := range c.Cfg.Dirs {
		abs := filepath.Join(c.Root, filepath.FromSlash(rel))
		st, err := CheckGitignore(abs)
		if err != nil {
			c.Logger.Warn("gitignore check failed", "dir_alias", alias, "dir", abs, "err", err)
			continue
		}
		if !st.Exists {
			c.Logger.Warn("missing .gitignore for secrets directory", "dir_alias", alias, "dir", abs)
			continue
		}
		if !st.KeepsSelfOnly {
			c.Logger.Warn(".gitignore does not look like 'ignore everything except itself'", "dir_alias", alias, "dir", abs, "path", st.Path)
		}
	}

	secretRecipients, envRefs, err := c.buildRecipientPlan()
	if err != nil {
		return err
	}
	if len(secretRecipients) == 0 {
		return errors.New("no secrets referenced in envs")
	}

	// Encrypt individual secrets.
	for ref, recips := range secretRecipients {
		storePath, err := c.StoreSecretPath(ref)
		if err != nil {
			return err
		}

		plainPath, err := c.PlaintextPath(ref)
		if err != nil {
			return err
		}

		plain, plainExists, err := ReadFileIfExists(plainPath)
		if err != nil {
			return err
		}

		var existing *SecretV1
		if b, ok, err := ReadFileIfExists(storePath); err != nil {
			return err
		} else if ok {
			k, err := ReadKind(b)
			if err != nil {
				return fmt.Errorf("read %s: %w", storePath, err)
			}
			if k != "secret/v1" {
				return fmt.Errorf("%s: unsupported kind %q", storePath, k)
			}
			ex, err := ParseSecretV1(b)
			if err != nil {
				return fmt.Errorf("parse %s: %w", storePath, err)
			}
			existing = ex
		}

		if !plainExists {
			if existing != nil {
				c.Logger.Warn("plaintext missing; keeping existing encrypted secret", "secret", ref.String(), "plaintext", plainPath)
				continue
			}
			return fmt.Errorf("plaintext missing and no encrypted secret exists: %s", plainPath)
		}

		sha := SHA256Hex(plain)
		recips = NormalizeRecipients(recips)

		if existing != nil {
			if existing.Secret.PlaintextSHA256 == sha && equalStringSlices(existing.Secret.Recipients, recips) {
				// unchanged: do not touch the file.
				continue
			}
		}

		ageRecips, err := ParseRecipients(recips)
		if err != nil {
			return err
		}
		cipher, err := EncryptBytes(plain, ageRecips...)
		if err != nil {
			return err
		}

		sec := &SecretV1{
			Kind: "secret/v1",
			Secret: SecretBody{
				Name:            ref.Name,
				PlaintextSHA256: sha,
				Payload:         EncodePayload(cipher),
				Recipients:      recips,
			},
		}
		out, err := MarshalSecretStable(sec)
		if err != nil {
			return err
		}
		if err := AtomicWriteFile(storePath, out, 0o600); err != nil {
			return err
		}
		c.Logger.Info("encrypted", "secret", ref.String(), "out", storePath, "recipients", len(recips))
	}

	// Build compiled environments.
	for envName, refs := range envRefs {
		envPath, err := c.StoreEnvPath(envName)
		if err != nil {
			return err
		}

		var embedded []SecretV1
		seenName := map[string]bool{}
		for _, ref := range refs {
			storePath, err := c.StoreSecretPath(ref)
			if err != nil {
				return err
			}
			b, ok, err := ReadFileIfExists(storePath)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("missing encrypted secret for env %q: %s", envName, storePath)
			}
			s, err := ParseSecretV1(b)
			if err != nil {
				return fmt.Errorf("parse %s: %w", storePath, err)
			}
			// De-dup by secret name in env artifact to avoid duplicates.
			if seenName[s.Secret.Name] {
				continue
			}
			seenName[s.Secret.Name] = true
			embedded = append(embedded, *s)
		}
		env := &EnvironmentV1{
			Kind:        "environment/v1",
			Environment: EnvironmentBody{Name: envName, Secrets: embedded},
		}
		out, err := MarshalEnvironmentStable(env)
		if err != nil {
			return err
		}

		if prev, ok, err := ReadFileIfExists(envPath); err != nil {
			return err
		} else if ok {
			if bytesEqual(prev, out) {
				continue
			}
		}

		if err := AtomicWriteFile(envPath, out, 0o600); err != nil {
			return err
		}
		c.Logger.Info("compiled env", "env", envName, "out", envPath, "secrets", len(embedded))
	}

	return nil
}

func (c *Cage) buildRecipientPlan() (map[SecretRef][]string, map[string][]SecretRef, error) {
	secretRecipients := map[SecretRef]map[string]struct{}{}
	envRefs := map[string][]SecretRef{}

	for envName, e := range c.Cfg.Envs {
		keys, err := ResolveRecipientRefs(c.Cfg, e.Recipients)
		if err != nil {
			return nil, nil, fmt.Errorf("env %q recipients: %w", envName, err)
		}
		for _, fspec := range e.Files {
			ref, err := ParseSecretRef(fspec)
			if err != nil {
				return nil, nil, fmt.Errorf("env %q file %q: %w", envName, fspec, err)
			}
			if _, ok := c.Cfg.Dirs[ref.Dir]; !ok {
				return nil, nil, fmt.Errorf("env %q references unknown dir alias %q in %q", envName, ref.Dir, fspec)
			}

			envRefs[envName] = append(envRefs[envName], ref)
			set, ok := secretRecipients[ref]
			if !ok {
				set = map[string]struct{}{}
				secretRecipients[ref] = set
			}
			for _, k := range keys {
				set[k] = struct{}{}
			}
		}
	}

	outRecipients := map[SecretRef][]string{}
	for ref, set := range secretRecipients {
		var keys []string
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		outRecipients[ref] = keys
	}

	// For stable processing, sort envRefs by secret ref string? Not needed.
	return outRecipients, envRefs, nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
