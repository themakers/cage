package libcage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Local state of a working copy: .cage/local/ (git-ignored, see
// gitignore.go). For each secret the base — a byte-for-byte copy of the
// store file the plaintext was last synchronized with — and the previous
// base (the common ancestor when two people encrypted the same secret).

func (c *Cage) LocalDir() string { return filepath.Join(c.CageDir(), "local") }

func (c *Cage) basePath(ref SecretRef) (string, error) {
	sp, err := c.StoreSecretPath(ref)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(c.StoreDir(), sp)
	if err != nil {
		return "", err
	}
	return filepath.Join(c.LocalDir(), "base", rel), nil
}

// version — one version of a secret: content hash, history and the store
// file it comes from (nil for a plaintext).
type version struct {
	SHA     string
	History []string
	File    *SecretV1
	Raw     []byte
}

func (v *version) has(sha string) bool {
	if v == nil {
		return false
	}
	for _, h := range v.History {
		if h == sha {
			return true
		}
	}
	return false
}

func parseVersion(raw []byte, path string) (*version, error) {
	s, err := ParseSecretV1(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &version{SHA: s.Secret.PlaintextSHA256, History: s.Secret.History, File: s, Raw: raw}, nil
}

func (c *Cage) readStoreVersion(ref SecretRef) (*version, error) {
	p, err := c.StoreSecretPath(ref)
	if err != nil {
		return nil, err
	}
	raw, ok, err := ReadFileIfExists(p)
	if err != nil || !ok {
		return nil, err
	}
	return parseVersion(raw, p)
}

func (c *Cage) readBase(ref SecretRef, prev bool) (*version, error) {
	p, err := c.basePath(ref)
	if err != nil {
		return nil, err
	}
	if prev {
		p += ".prev"
	}
	raw, ok, err := ReadFileIfExists(p)
	if err != nil || !ok {
		return nil, err
	}
	return parseVersion(raw, p)
}

// setBase records store version s as the base of ref. The old base becomes
// the previous one when it differs.
func (c *Cage) setBase(ref SecretRef, s *version) error {
	p, err := c.basePath(ref)
	if err != nil {
		return err
	}
	if old, ok, err := ReadFileIfExists(p); err != nil {
		return err
	} else if ok {
		if BytesEqual(old, s.Raw) {
			return nil
		}
		if ov, err := parseVersion(old, p); err == nil && ov.SHA != s.SHA {
			if err := AtomicWriteFile(p+".prev", old, 0o600); err != nil {
				return err
			}
		}
	}
	return AtomicWriteFile(p, s.Raw, 0o600)
}

// removeBase drops the base (and the previous base) of ref.
func (c *Cage) removeBase(ref SecretRef) error {
	p, err := c.basePath(ref)
	if err != nil {
		return err
	}
	for _, f := range []string{p, p + ".prev"} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// baseRefs — secrets that have a base (to find ones removed from cage.yaml).
func (c *Cage) baseRefs() []SecretRef {
	var out []SecretRef
	root := filepath.Join(c.LocalDir(), "base", "files")
	dirs, _ := os.ReadDir(root)
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(root, d.Name()))
		for _, f := range files {
			if name, ok := strings.CutSuffix(f.Name(), ".cage"); ok && !f.IsDir() {
				out = append(out, SecretRef{Dir: d.Name(), Name: name})
			}
		}
	}
	return out
}

// decryptSecret decrypts a store secret and verifies its content hash: a
// mismatch means the file was corrupted (e.g. by a manual git merge).
func (c *Cage) decryptSecret(s *SecretV1) ([]byte, error) {
	plain, err := c.decryptSecretPayload(s.Secret.Payload)
	if err != nil {
		return nil, err
	}
	if s.Secret.PlaintextSHA256 != "" && SHA256Hex(plain) != s.Secret.PlaintextSHA256 {
		return nil, fmt.Errorf("%s: store file is corrupted (content does not match plaintext_sha256)", s.Secret.Name)
	}
	return plain, nil
}
