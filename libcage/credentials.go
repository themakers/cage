package libcage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Service credentials: cage ciphertext is decrypted by a trusted preparer
// with an explicitly configured machine identity, composed into named
// credentials and published into a private non-swappable staging directory,
// from which systemd loads them (LoadCredential=) into the consumer unit.
// Values never pass through environment variables, arguments or output.

const (
	CredentialsManifestVersion = 1
	// CredentialsMaxTotalSize mirrors the systemd limit on the accumulated
	// size of credentials per unit.
	CredentialsMaxTotalSize = 1 << 20
)

type CredentialsManifest struct {
	Version     int                  `json:"version"`
	Unit        string               `json:"unit"`
	Identity    string               `json:"identity"`
	StagingDir  string               `json:"stagingDir"`
	Credentials []CredentialManifest `json:"credentials"`
}

type CredentialManifest struct {
	Name    string             `json:"name"`
	Sources []CredentialSource `json:"sources"`
}

type CredentialSource struct {
	Path   string `json:"path"`
	Prefix string `json:"prefix,omitempty"`
}

var (
	credentialUnitRe   = regexp.MustCompile(`^[A-Za-z0-9_.@:\\-]+$`)
	credentialNameRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	credentialPrefixRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

func LoadCredentialsManifest(path string) (*CredentialsManifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m CredentialsManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("manifest %s: %w", path, err)
	}
	return &m, nil
}

func (m *CredentialsManifest) Validate() error {
	if m.Version != CredentialsManifestVersion {
		return fmt.Errorf("unsupported version %d (expected %d)", m.Version, CredentialsManifestVersion)
	}
	if !credentialUnitRe.MatchString(m.Unit) || m.Unit == "." || m.Unit == ".." {
		return fmt.Errorf("invalid unit name %q", m.Unit)
	}
	if !isCleanAbs(m.Identity) {
		return fmt.Errorf("identity must be a clean absolute path, got %q", m.Identity)
	}
	if !isCleanAbs(m.StagingDir) || m.StagingDir == "/" {
		return fmt.Errorf("stagingDir must be a clean absolute path other than /, got %q", m.StagingDir)
	}
	if len(m.Credentials) == 0 {
		return fmt.Errorf("no credentials")
	}
	seen := map[string]bool{}
	for _, c := range m.Credentials {
		if !credentialNameRe.MatchString(c.Name) {
			return fmt.Errorf("invalid credential name %q", c.Name)
		}
		if seen[c.Name] {
			return fmt.Errorf("duplicate credential %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.Sources) == 0 {
			return fmt.Errorf("credential %s: no sources", c.Name)
		}
		for _, s := range c.Sources {
			if !isCleanAbs(s.Path) || !strings.HasSuffix(s.Path, ".cage") {
				return fmt.Errorf("credential %s: source must be a clean absolute *.cage path, got %q", c.Name, s.Path)
			}
			if s.Prefix != "" && !credentialPrefixRe.MatchString(s.Prefix) {
				return fmt.Errorf("credential %s: invalid prefix %q", c.Name, s.Prefix)
			}
		}
	}
	return nil
}

func isCleanAbs(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p
}

// ComposeCredentials decrypts every source with the manifest identity and
// returns the complete credential set, or an error and nothing. Errors name
// credentials, sources and variables, never values. A credential is either
// one blob or a dotenv bundle of one or more .env secrets/environments
// (optionally prefixed); colliding variable names are an error.
func ComposeCredentials(lg *slog.Logger, m *CredentialsManifest) (map[string][]byte, error) {
	ids, err := LoadIdentityFile(m.Identity)
	if err != nil {
		return nil, err
	}
	c := &Cage{Logger: lg, Ids: ids}
	out := map[string][]byte{}
	fail := func(err error) (map[string][]byte, error) {
		ClearCredentials(out)
		return nil, err
	}
	total := 0
	for _, cred := range m.Credentials {
		specs := make([]string, 0, len(cred.Sources))
		for _, s := range cred.Sources {
			if s.Prefix != "" {
				specs = append(specs, s.Prefix+"="+s.Path)
			} else {
				specs = append(specs, s.Path)
			}
		}
		var buf bytes.Buffer
		if err := c.Dump(specs, &buf); err != nil {
			return fail(fmt.Errorf("credential %s: %w", cred.Name, err))
		}
		if buf.Len() == 0 {
			return fail(fmt.Errorf("credential %s: empty", cred.Name))
		}
		total += buf.Len()
		if total > CredentialsMaxTotalSize {
			return fail(fmt.Errorf("credentials of unit %s exceed %d bytes in total (systemd limit)", m.Unit, CredentialsMaxTotalSize))
		}
		out[cred.Name] = buf.Bytes()
	}
	return out, nil
}

// ClearCredentials overwrites credential buffers (best effort: copies made
// by the Go runtime are not reachable).
func ClearCredentials(creds map[string][]byte) {
	for k, v := range creds {
		clear(v)
		delete(creds, k)
	}
}

// CredentialsTarget is the staging directory of the unit's published set.
func (m *CredentialsManifest) CredentialsTarget() string {
	return filepath.Join(m.StagingDir, m.Unit)
}
