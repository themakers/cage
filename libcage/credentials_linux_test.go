//go:build linux

package libcage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishCredentials(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "staging")
	mustOK(t, os.Mkdir(staging, 0o700))
	m := &CredentialsManifest{
		Version: 1, Unit: "app.service", Identity: "/k", StagingDir: staging,
		Credentials: []CredentialManifest{
			{Name: "config", Sources: []CredentialSource{{Path: "/a.cage"}}},
			{Name: "tls.key", Sources: []CredentialSource{{Path: "/b.cage"}}},
		},
	}

	// Real staging must be ramfs; a test directory never is.
	mustErr(t, PublishCredentials(m, map[string][]byte{"config": []byte("A=1\n"), "tls.key": []byte("k")}), "ramfs")

	requireRamfs = false
	t.Cleanup(func() { requireRamfs = true })

	mustOK(t, PublishCredentials(m, map[string][]byte{"config": []byte("A=1\n"), "tls.key": []byte("k")}))
	target := m.CredentialsTarget()
	for name, want := range map[string]string{"config": "A=1\n", "tls.key": "k"} {
		p := filepath.Join(target, name)
		st, err := os.Lstat(p)
		mustOK(t, err)
		if st.Mode().Perm() != 0o600 || !st.Mode().IsRegular() {
			t.Fatalf("%s: mode %v", name, st.Mode())
		}
		b, err := os.ReadFile(p)
		mustOK(t, err)
		if string(b) != want {
			t.Fatalf("%s: unexpected content", name)
		}
	}

	// Republishing replaces the whole set; leftovers of interrupted runs go.
	mustOK(t, os.Mkdir(filepath.Join(staging, ".app.service#123"), 0o700))
	mustOK(t, os.Mkdir(filepath.Join(staging, ".app.service-other#1"), 0o700))
	mustOK(t, PublishCredentials(m, map[string][]byte{"config": []byte("A=2\n"), "tls.key": []byte("k2")}))
	b, err := os.ReadFile(filepath.Join(target, "config"))
	mustOK(t, err)
	if string(b) != "A=2\n" {
		t.Fatalf("set not replaced")
	}
	if _, err := os.Stat(filepath.Join(staging, ".app.service#123")); !os.IsNotExist(err) {
		t.Fatalf("leftover not removed")
	}
	if _, err := os.Stat(filepath.Join(staging, ".app.service-other#1")); err != nil {
		t.Fatalf("other unit's directory must stay: %v", err)
	}

	mustOK(t, CleanCredentials(m))
	mustOK(t, CleanCredentials(m)) // idempotent
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("clean must remove the set")
	}

	// Staging accessible to others is refused.
	mustOK(t, os.Chmod(staging, 0o755))
	mustErr(t, PublishCredentials(m, map[string][]byte{"config": []byte("A=1\n"), "tls.key": []byte("k")}), "must not be accessible")

	// Missing staging: clean is a no-op, publish fails.
	m.StagingDir = filepath.Join(t.TempDir(), "missing")
	mustOK(t, CleanCredentials(m))
	mustErr(t, PublishCredentials(m, map[string][]byte{"config": []byte("A=1\n"), "tls.key": []byte("k")}), "no such file")
}
