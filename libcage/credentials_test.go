package libcage

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// credFixture: a cage root encrypted for one machine key, written to a file
// as a service would have it.
type credFixture struct {
	c        *Cage
	identity string // private key file of the machine
	other    string // private key file of a non-recipient
}

func writeKeyFile(t *testing.T, dir, name, passphrase string) (path string, key testKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if passphrase == "" {
		ids, err := LoadIdentityFile(path)
		if err != nil {
			t.Fatal(err)
		}
		key = testKey{pub: ids.SSH[0].PublicKey, id: ids.SSH[0]}
	}
	return path, key
}

func newCredFixture(t *testing.T) *credFixture {
	t.Helper()
	keys := t.TempDir()
	idPath, machine := writeKeyFile(t, keys, "machine", "")
	otherPath, _ := writeKeyFile(t, keys, "other", "")
	root := t.TempDir()
	cfg := `kind: cage/v1
dirs:
  default: .cage/secrets
recipients:
  machine:
    - ` + machine.pub + `
envs:
  app:
    files: [db.env, api.env, tls-key, clash.env]
    recipients: [machine]
`
	if err := os.MkdirAll(filepath.Join(root, ".cage", "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".cage", "cage.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	c := openTestCage(t, root, machine)
	writePlain(t, c, "db.env", "USER=app\nPASSWORD=db-secret-value\n")
	writePlain(t, c, "api.env", "TOKEN=api-secret-value\n")
	writePlain(t, c, "clash.env", "PASSWORD=other\n")
	writePlain(t, c, "tls-key", "-----BEGIN FAKE KEY-----\nblob-secret-value\n")
	mustOK(t, c.EncryptAll())
	return &credFixture{c: c, identity: idPath, other: otherPath}
}

func (f *credFixture) file(t *testing.T, ref string) string {
	t.Helper()
	r, err := ParseSecretRef(ref)
	mustOK(t, err)
	p, err := f.c.StoreSecretPath(r)
	mustOK(t, err)
	return p
}

// plainAsCage: plaintext mistakenly named *.cage; errors must not quote it.
func (f *credFixture) plainAsCage(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain.cage")
	mustOK(t, os.WriteFile(p, []byte("kind: [db-secret-value\nPASSWORD: db-secret-value\n"), 0o600))
	return p
}

func (f *credFixture) manifest(t *testing.T, creds ...CredentialManifest) *CredentialsManifest {
	t.Helper()
	m := &CredentialsManifest{
		Version:     CredentialsManifestVersion,
		Unit:        "app.service",
		Identity:    f.identity,
		StagingDir:  "/run/cage-credentials",
		Credentials: creds,
	}
	mustOK(t, m.Validate())
	return m
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestComposeCredentials(t *testing.T) {
	f := newCredFixture(t)
	envPath, err := f.c.StoreEnvPath("app")
	mustOK(t, err)

	m := f.manifest(t,
		CredentialManifest{Name: "config", Sources: []CredentialSource{
			{Path: f.file(t, "db.env"), Prefix: "DB_"},
			{Path: f.file(t, "api.env")},
		}},
		CredentialManifest{Name: "tls.key", Sources: []CredentialSource{{Path: f.file(t, "tls-key")}}},
	)
	creds, err := ComposeCredentials(quietLogger(), m)
	mustOK(t, err)
	cfg, err := ParseDotenv(creds["config"])
	mustOK(t, err)
	if cfg["DB_PASSWORD"] != "db-secret-value" || cfg["TOKEN"] != "api-secret-value" || len(cfg) != 3 {
		t.Fatalf("config: %v", cfg)
	}
	if !strings.Contains(string(creds["tls.key"]), "blob-secret-value") {
		t.Fatalf("blob credential not decrypted")
	}

	// An environment bundle skips blobs and checks collisions.
	_, err = ComposeCredentials(quietLogger(), f.manifest(t,
		CredentialManifest{Name: "env", Sources: []CredentialSource{{Path: envPath}}}))
	mustErr(t, err, "defined by both")

	for _, tc := range []struct {
		name    string
		m       *CredentialsManifest
		mutate  func(m *CredentialsManifest)
		wantErr string
	}{
		{"collision", f.manifest(t, CredentialManifest{Name: "c", Sources: []CredentialSource{
			{Path: f.file(t, "db.env")}, {Path: f.file(t, "clash.env")}}}), nil, "defined by both"},
		{"blob with env", f.manifest(t, CredentialManifest{Name: "c", Sources: []CredentialSource{
			{Path: f.file(t, "db.env")}, {Path: f.file(t, "tls-key")}}}), nil, "cannot mix"},
		{"prefixed blob", f.manifest(t, CredentialManifest{Name: "c", Sources: []CredentialSource{
			{Path: f.file(t, "tls-key"), Prefix: "X_"}}}), nil, "prefix is not applicable"},
		{"wrong identity", f.manifest(t, CredentialManifest{Name: "c", Sources: []CredentialSource{
			{Path: f.file(t, "db.env")}}}), func(m *CredentialsManifest) { m.Identity = f.other }, "credential c"},
		{"missing source", f.manifest(t, CredentialManifest{Name: "c", Sources: []CredentialSource{
			{Path: "/nonexistent/x.cage"}}}), nil, "no such file"},
		{"plaintext as source", f.manifest(t, CredentialManifest{Name: "c", Sources: []CredentialSource{
			{Path: f.plainAsCage(t)}}}), nil, "not a valid cage file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mutate != nil {
				tc.mutate(tc.m)
			}
			creds, err := ComposeCredentials(quietLogger(), tc.m)
			mustErr(t, err, tc.wantErr)
			if creds != nil {
				t.Fatalf("a failed composition must return nothing")
			}
			for _, v := range []string{"db-secret-value", "api-secret-value", "blob-secret-value"} {
				if strings.Contains(err.Error(), v) {
					t.Fatalf("error leaks a value: %v", err)
				}
			}
		})
	}
}

func TestCredentialsManifestValidate(t *testing.T) {
	ok := func() CredentialsManifest {
		return CredentialsManifest{
			Version:    1,
			Unit:       "app@1.service",
			Identity:   "/etc/ssh/ssh_host_ed25519_key",
			StagingDir: "/run/cage-credentials",
			Credentials: []CredentialManifest{{Name: "config", Sources: []CredentialSource{
				{Path: "/nix/store/x-app.cage", Prefix: "APP_"}}}},
		}
	}
	m := ok()
	mustOK(t, m.Validate())
	for name, mutate := range map[string]func(*CredentialsManifest){
		"version":         func(m *CredentialsManifest) { m.Version = 2 },
		"unit traversal":  func(m *CredentialsManifest) { m.Unit = ".." },
		"unit slash":      func(m *CredentialsManifest) { m.Unit = "a/b" },
		"relative id":     func(m *CredentialsManifest) { m.Identity = "key" },
		"unclean staging": func(m *CredentialsManifest) { m.StagingDir = "/run/../tmp" },
		"root staging":    func(m *CredentialsManifest) { m.StagingDir = "/" },
		"no creds":        func(m *CredentialsManifest) { m.Credentials = nil },
		"bad name":        func(m *CredentialsManifest) { m.Credentials[0].Name = "../x" },
		"dup name": func(m *CredentialsManifest) {
			m.Credentials = append(m.Credentials, m.Credentials[0])
		},
		"no sources":   func(m *CredentialsManifest) { m.Credentials[0].Sources = nil },
		"not .cage":    func(m *CredentialsManifest) { m.Credentials[0].Sources[0].Path = "/x.env" },
		"bad prefix":   func(m *CredentialsManifest) { m.Credentials[0].Sources[0].Prefix = "1X" },
		"relative src": func(m *CredentialsManifest) { m.Credentials[0].Sources[0].Path = "x.cage" },
	} {
		m := ok()
		mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}

	p := filepath.Join(t.TempDir(), "m.json")
	mustOK(t, os.WriteFile(p, []byte(`{"version":1,"unit":"a","identity":"/k","stagingDir":"/s","credentials":[],"extra":1}`), 0o644))
	_, err := LoadCredentialsManifest(p)
	mustErr(t, err, "unknown field")
}

func TestLoadIdentityFile(t *testing.T) {
	dir := t.TempDir()
	p, _ := writeKeyFile(t, dir, "k", "")
	mustOK(t, os.Chmod(p, 0o640))
	_, err := LoadIdentityFile(p)
	mustErr(t, err, "must not be accessible")

	pp, _ := writeKeyFile(t, dir, "protected", "pass")
	_, err = LoadIdentityFile(pp)
	mustErr(t, err, "passphrase-protected")

	_, err = LoadIdentityFile("relative")
	mustErr(t, err, "absolute")
}

func TestParseDotenvErrorHidesContent(t *testing.T) {
	_, err := ParseDotenv([]byte("GOOD=1\nthis is a hidden-secret-value\n"))
	mustErr(t, err, "line 2")
	if strings.Contains(err.Error(), "hidden-secret-value") {
		t.Fatalf("error leaks content: %v", err)
	}
	_, err = ParseDotenv([]byte("A=\"unclosed hidden-secret-value\n"))
	mustErr(t, err, "unclosed")
	if strings.Contains(err.Error(), "hidden-secret-value") {
		t.Fatalf("error leaks content: %v", err)
	}
}
