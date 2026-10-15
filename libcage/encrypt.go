package libcage

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

func (c *Cage) EncryptAll() error {
	if c.Root == "" || c.Cfg == nil {
		return fmt.Errorf("EncryptAll requires cage root + loaded config")
	}
	if err := c.EnsureStoreDirs(); err != nil {
		return err
	}

	if err := c.WriteGitignore(); err != nil {
		return err
	}

	secretRecipients, envRefs, err := c.buildRecipientPlan()
	if err != nil {
		return err
	}
	if len(secretRecipients) == 0 {
		return errors.New("no secrets referenced in envs")
	}

	//> Phase 1: check everything, write nothing on refusal. A plaintext that
	//> is behind or diverged from the store would silently revert someone
	//> else's change.
	states := map[SecretRef]syncInfo{}
	var refusals []string
	for ref := range secretRecipients {
		in, err := c.syncState(ref)
		if err != nil {
			return fmt.Errorf("%s: %w", ref, err)
		}
		states[ref] = in
		if err := requireEditable(ref, in); err != nil {
			refusals = append(refusals, err.Error())
			continue
		}
		//> Only what is about to be published must parse.
		if in.Plain != nil && IsEnvSecretName(ref.Name) && (in.S == nil || in.S.SHA != in.L) {
			if _, err := ParseDotenv(in.Plain); err != nil {
				refusals = append(refusals, fmt.Sprintf("%s: does not parse: %v", ref, err))
			}
		}
	}
	if len(refusals) > 0 {
		sort.Strings(refusals)
		return errors.New("encrypt refused, nothing written:\n  " + strings.Join(refusals, "\n  "))
	}

	// Phase 2: encrypt individual secrets.
	for ref, recips := range secretRecipients {
		in := states[ref]
		storePath, err := c.StoreSecretPath(ref)
		if err != nil {
			return err
		}

		if in.Plain == nil {
			if in.S != nil {
				c.Logger.Debug("plaintext missing; keeping existing encrypted secret", "secret", ref.String())
				continue
			}
			return fmt.Errorf("plaintext missing and no encrypted secret exists: %s", ref)
		}
		plain := in.Plain

		sha := in.L
		recips = NormalizeRecipients(recips)

		var history []string
		if in.S != nil {
			if in.S.SHA == sha && equalStringSlices(in.S.File.Secret.Recipients, recips) {
				// unchanged: do not touch the file; record the base.
				if err := c.setBase(ref, in.S); err != nil {
					return err
				}
				continue
			}
			history = in.S.History
			if in.S.SHA != sha {
				history = append([]string{in.S.SHA}, in.S.History...)
			}
			if len(history) > HistoryLimit {
				history = history[:HistoryLimit]
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
				History:         history,
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
		if err := c.setBase(ref, &version{SHA: sha, History: history, File: sec, Raw: out}); err != nil {
			return err
		}
		c.Logger.Info("encrypted", "secret", ref.String(), "out", storePath, "recipients", len(recips))
	}

	//> Compiled envs are derived from store files and always rebuilt (a git
	//> conflict in one is resolved by this; the old content is never parsed).
	for envName, refs := range envRefs {
		envPath, err := c.StoreEnvPath(envName)
		if err != nil {
			return err
		}
		out, err := c.compileEnv(envName, refs)
		if err != nil {
			return err
		}
		if prev, ok, err := ReadFileIfExists(envPath); err != nil {
			return err
		} else if ok && bytesEqual(prev, out) {
			continue
		}
		if err := AtomicWriteFile(envPath, out, 0o600); err != nil {
			return err
		}
		c.Logger.Info("compiled env", "env", envName, "out", envPath)
	}

	return nil
}

// compileEnv — content of a compiled env from the current store files.
func (c *Cage) compileEnv(envName string, refs []SecretRef) ([]byte, error) {
	var embedded []SecretV1
	seenName := map[string]bool{}
	for _, ref := range refs {
		s, err := c.readStoreVersion(ref)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, fmt.Errorf("missing encrypted secret for env %q: %s", envName, ref)
		}
		// De-dup by secret name in env artifact to avoid duplicates.
		if seenName[s.File.Secret.Name] {
			continue
		}
		seenName[s.File.Secret.Name] = true
		embedded = append(embedded, *s.File)
	}
	return MarshalEnvironmentStable(&EnvironmentV1{
		Kind:        "environment/v1",
		Environment: EnvironmentBody{Name: envName, Secrets: embedded},
	})
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
