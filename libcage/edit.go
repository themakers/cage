package libcage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Editing works on plaintext files (comments and order preserved); a
// missing plaintext is restored from the store first. Values never leave
// the process: callers get names only.

// ReadPlainForEdit returns the plaintext of ref for a local change: the
// secret must not be behind or diverged from the store; a missing plaintext
// is restored from the store (and the base recorded); nil — a new secret.
func (c *Cage) ReadPlainForEdit(ref SecretRef) ([]byte, error) {
	in, err := c.syncState(ref)
	if err != nil {
		return nil, err
	}
	if err := requireEditable(ref, in); err != nil {
		return nil, err
	}
	if in.State != SyncNew {
		return in.Plain, nil
	}
	plain, err := c.decryptSecret(in.S.File)
	if isNotRecipient(err) {
		return nil, fmt.Errorf("%s: not a recipient of this secret", ref)
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", ref, err)
	}
	if err := c.WritePlain(ref, plain); err != nil {
		return nil, err
	}
	if err := c.setBase(ref, in.S); err != nil {
		return nil, err
	}
	return plain, nil
}

// ReplacePlain overwrites a secret as a deliberate replacement of the
// current store version, even one this identity can not read (rotating
// another engineer's credentials): the current store version becomes the
// base, so the next encrypt publishes the replacement on top of it.
func (c *Cage) ReplacePlain(ref SecretRef, data []byte) error {
	s, err := c.readStoreVersion(ref)
	if err != nil {
		return err
	}
	if err := c.WritePlain(ref, data); err != nil {
		return err
	}
	if s == nil {
		return c.removeBase(ref)
	}
	return c.setBase(ref, s)
}

// WritePlain writes the plaintext of ref (0600).
func (c *Cage) WritePlain(ref SecretRef, data []byte) error {
	p, err := c.PlaintextPath(ref)
	if err != nil {
		return err
	}
	return AtomicWriteFile(p, data, 0o600)
}

// EditEnv applies fn to the .env secret ref and writes it back if valid.
func (c *Cage) EditEnv(ref SecretRef, fn func(*DotenvFile) error) error {
	if !IsEnvSecretName(ref.Name) {
		return fmt.Errorf("%s is not a .env secret", ref)
	}
	plain, err := c.ReadPlainForEdit(ref)
	if err != nil {
		return err
	}
	f := ParseDotenvFile(plain)
	if err := fn(f); err != nil {
		return err
	}
	if err := f.Validate(); err != nil {
		return fmt.Errorf("%s: result does not parse: %w", ref, err)
	}
	return c.WritePlain(ref, f.Bytes())
}

// MoveVar moves KEY from src to dst (as newKey). The value is removed from
// src only after it is written to dst.
func (c *Cage) MoveVar(src SecretRef, key string, dst SecretRef, newKey string) error {
	if newKey == "" {
		newKey = key
	}
	if src == dst && key == newKey {
		return nil
	}
	plain, err := c.ReadPlainForEdit(src)
	if err != nil {
		return err
	}
	value, ok, err := ParseDotenvFile(plain).Get(key)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s: no variable %s", src, key)
	}
	if err := c.EditEnv(dst, func(f *DotenvFile) error {
		if src != dst && f.Has(newKey) {
			return fmt.Errorf("%s: variable %s already exists", dst, newKey)
		}
		return f.Set(newKey, value)
	}); err != nil {
		return err
	}
	return c.EditEnv(src, func(f *DotenvFile) error {
		f.Remove(key)
		return nil
	})
}

// MoveSecret renames a secret: the plaintext (restored from the store if
// missing) is written as dst, then src files are removed. dst is encrypted
// by the next encrypt (it must be listed in cage.yaml).
func (c *Cage) MoveSecret(src, dst SecretRef) error {
	if src == dst {
		return nil
	}
	if IsEnvSecretName(src.Name) != IsEnvSecretName(dst.Name) {
		return fmt.Errorf("mv: %s and %s must both be .env secrets or both blobs", src, dst)
	}
	if p, err := c.PlaintextPath(dst); err != nil {
		return err
	} else if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("mv: %s already exists", dst)
	}
	if s, err := c.StoreSecretPath(dst); err != nil {
		return err
	} else if _, err := os.Stat(s); err == nil {
		return fmt.Errorf("mv: %s already exists in the store", dst)
	}
	plain, err := c.ReadPlainForEdit(src)
	if err != nil {
		return err
	}
	if plain == nil {
		return fmt.Errorf("mv: %s does not exist", src)
	}
	if err := c.WritePlain(dst, plain); err != nil {
		return err
	}
	return c.RemoveSecretFiles(src)
}

// RemoveSecretFiles deletes the plaintext, the store file and the base of
// ref.
func (c *Cage) RemoveSecretFiles(ref SecretRef) error {
	p, err := c.PlaintextPath(ref)
	if err != nil {
		return err
	}
	s, err := c.StoreSecretPath(ref)
	if err != nil {
		return err
	}
	for _, f := range []string{p, p + ".store", s} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return c.removeBase(ref)
}

// ReferencedBy lists envs of cage.yaml that include ref.
func (c *Cage) ReferencedBy(ref SecretRef) []string {
	var out []string
	for name, env := range c.Cfg.Envs {
		for _, fs := range env.Files {
			if r, err := ParseSecretRef(fs); err == nil && r == ref {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// Generate produces a random value by spec "random:<enc>:<bytes>" where enc
// is base64, base64url, hex or alnum.
func Generate(spec string) (string, error) {
	parts := strings.Split(spec, ":")
	if len(parts) != 3 || parts[0] != "random" {
		return "", fmt.Errorf("generator %q: expected random:<base64|base64url|hex|alnum>:<bytes>", spec)
	}
	n, err := strconv.Atoi(parts[2])
	if err != nil || n < 8 || n > 1024 {
		return "", fmt.Errorf("generator %q: size must be 8..1024", spec)
	}
	if parts[1] == "alnum" {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		out := make([]byte, n)
		for i := range out {
			k, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
			if err != nil {
				return "", err
			}
			out[i] = alphabet[k.Int64()]
		}
		return string(out), nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	switch parts[1] {
	case "base64":
		return base64.StdEncoding.EncodeToString(b), nil
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(b), nil
	case "hex":
		return hex.EncodeToString(b), nil
	default:
		return "", fmt.Errorf("generator %q: unknown encoding %q", spec, parts[1])
	}
}

// KeygenSSHEd25519 writes a new OpenSSH ed25519 private key as the blob
// secret ref and returns the public key line.
func (c *Cage) KeygenSSHEd25519(ref SecretRef, comment string) (string, error) {
	if IsEnvSecretName(ref.Name) {
		return "", fmt.Errorf("%s: keys are blob secrets (name must not end with .env)", ref)
	}
	if p, err := c.PlaintextPath(ref); err != nil {
		return "", err
	} else if _, err := os.Stat(p); err == nil {
		return "", fmt.Errorf("%s already exists (%s)", ref, filepath.Base(p))
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return "", err
	}
	if err := c.WritePlain(ref, pem.EncodeToMemory(block)); err != nil {
		return "", err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return line, nil
}
