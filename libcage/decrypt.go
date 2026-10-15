package libcage

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// DecryptAll brings plaintexts up to date with the store without losing
// local changes:
//   - store newer, plaintext unchanged → plaintext updated;
//   - plaintext changed, store unchanged → kept;
//   - both changed → merged line by line, overlapping changes get conflict
//     markers (git style);
//   - store older than the base (revert, branch switch) → conflict, the
//     plaintext is kept.
//
// All secrets are processed; problems are reported together at the end.
func (c *Cage) DecryptAll() error {
	if c.Root == "" || c.Cfg == nil {
		return fmt.Errorf("DecryptAll requires cage root + loaded config")
	}
	if c.Ids.Empty() {
		return fmt.Errorf("no usable identities; set CAGE_SSH_IDENTITY or ensure ~/.ssh private keys exist")
	}
	if err := c.WriteGitignore(); err != nil {
		return err
	}

	var problems []string
	inConfig := map[SecretRef]bool{}
	for _, ref := range c.AllRefs() {
		inConfig[ref] = true
		msg, err := c.decryptOne(ref)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", ref, err))
		} else if msg != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", ref, msg))
		}
	}

	for _, ref := range c.baseRefs() {
		if inConfig[ref] {
			continue
		}
		if msg := c.dropRemoved(ref); msg != "" {
			problems = append(problems, fmt.Sprintf("%s: %s", ref, msg))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New("decrypt finished with problems:\n  " + strings.Join(problems, "\n  "))
	}
	return nil
}

// decryptOne — returns a conflict report (not an error: other secrets go on).
func (c *Cage) decryptOne(ref SecretRef) (string, error) {
	in, err := c.syncState(ref)
	if err != nil {
		return "", err
	}
	if in.S == nil {
		return "", nil
	}
	store, err := c.decryptSecret(in.S.File)
	if isNotRecipient(err) {
		//> Secrets addressed to other recipients (e.g. personal credentials
		//> of another engineer) are not ours to decrypt.
		c.Logger.Info("skipped: not a recipient", "secret", ref.String())
		return "", nil
	}
	if err != nil {
		return "", err
	}

	switch in.State {
	case SyncNew, SyncOutdated:
		if err := c.WritePlain(ref, store); err != nil {
			return "", err
		}
		c.Logger.Info("decrypted", "secret", ref.String())
		return "", c.setBase(ref, in.S)
	case SyncInSync:
		return "", c.setBase(ref, in.S)
	case SyncModified:
		return "", nil
	case SyncConflict:
		return "unresolved conflict (edit the file or `cage resolve`)", nil
	case SyncDiverged:
		return c.mergeInto(ref, in, store)
	}
	return "", nil
}

// mergeInto merges local changes with the store version; the result is
// based on the store version (base := S).
func (c *Cage) mergeInto(ref SecretRef, in syncInfo, store []byte) (string, error) {
	if !isText(in.Plain) || !isText(store) {
		sidecar, err := c.storeSidecar(ref)
		if err != nil {
			return "", err
		}
		if err := AtomicWriteFile(sidecar, store, 0o600); err != nil {
			return "", err
		}
		if err := c.setBase(ref, in.S); err != nil {
			return "", err
		}
		return "conflict: binary secret changed locally and in store; store version is in " + ref.Name + ".store — `cage resolve " + ref.String() + " -local|-store`", nil
	}

	var base []byte
	if !in.Older {
		ancestor, err := c.commonAncestor(ref, in)
		if err != nil {
			return "", err
		}
		base = ancestor
	}
	res := merge3(base, in.Plain, store)
	if err := c.WritePlain(ref, res.Text); err != nil {
		return "", err
	}
	if err := c.setBase(ref, in.S); err != nil {
		return "", err
	}
	if len(res.Conflicts) == 0 {
		c.Logger.Info("merged local changes with store", "secret", ref.String())
		return "", nil
	}
	what := "conflict"
	if in.Older {
		what = "conflict (store is older than your copy: revert or branch switch?)"
	} else if base == nil {
		what = "conflict (no common base; first run of this cage version on a changed file?)"
	}
	if keys := conflictKeys(res); len(keys) > 0 {
		what += " in " + strings.Join(keys, ", ")
	}
	return what + " — edit the file or `cage resolve " + ref.String() + " -local|-store`", nil
}

// commonAncestor — content of the base or the previous base if the store
// descends from it; nil if unknown.
func (c *Cage) commonAncestor(ref SecretRef, in syncInfo) ([]byte, error) {
	prev, err := c.readBase(ref, true)
	if err != nil {
		return nil, err
	}
	for _, v := range []*version{in.B, prev} {
		if v == nil || !(v.SHA == in.S.SHA || in.S.has(v.SHA)) {
			continue
		}
		plain, err := c.decryptSecret(v.File)
		if err != nil {
			return nil, fmt.Errorf("base: %w", err)
		}
		return plain, nil
	}
	return nil, nil
}

// dropRemoved — a secret with a base is no longer in cage.yaml: unchanged
// plaintext and base are removed; local changes are kept and reported.
func (c *Cage) dropRemoved(ref SecretRef) string {
	b, err := c.readBase(ref, false)
	if err != nil || b == nil {
		return ""
	}
	pp, err := c.PlaintextPath(ref)
	if err != nil {
		//> The dir alias itself is gone: keep everything, tell the user.
		return "removed from cage.yaml (dir alias gone); its base is left in .cage/local"
	}
	plain, ok, err := ReadFileIfExists(pp)
	if err != nil {
		return err.Error()
	}
	if ok && SHA256Hex(plain) != b.SHA {
		return "removed from cage.yaml but has unpublished local changes — move them (`cage mv`) or delete the file"
	}
	if ok {
		if err := os.Remove(pp); err != nil {
			return err.Error()
		}
	}
	if err := c.removeBase(ref); err != nil {
		return err.Error()
	}
	c.Logger.Info("removed secret dropped from cage.yaml", "secret", ref.String())
	return ""
}
