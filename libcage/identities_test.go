package libcage

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestIdentitiesFromSSHConfig_UsesLibsshParser: identity discovery через
// единый парсер ssh_config из libssh — с Include и wildcard-блоком.
func TestIdentitiesFromSSHConfig_UsesLibsshParser(t *testing.T) {
	tmp := t.TempDir()

	keyPath := filepath.Join(tmp, "id_ed25519_test")
	out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "test", "-f", keyPath, "-q").CombinedOutput()
	if err != nil {
		t.Skipf("ssh-keygen unavailable: %v (%s)", err, out)
	}

	confDir := filepath.Join(tmp, ".ssh")
	if err := os.MkdirAll(filepath.Join(confDir, "config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(confDir, "config")
	confBody := `
Include config.d/extra*

Host *
  AddKeysToAgent yes
  IdentityFile ` + keyPath + `
`
	if err := os.WriteFile(conf, []byte(confBody), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(confDir, "config.d", "extra")
	extraBody := `
Host ops
  HostName 10.1.2.3
  User root
  IdentityFile ` + keyPath + `
`
	if err := os.WriteFile(extra, []byte(extraBody), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", tmp)
	if os.Getenv("USERPROFILE") != "" {
		t.Setenv("USERPROFILE", tmp)
	}

	ids, err := identitiesFromSSHConfig(slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	// Хотя бы один SSHIdentity должен был распознаться по ключу из
	// Include'd Host-блока и wildcard-блока (оба указывают на один файл —
	// дедуп по пути ожидаем 1 identity).
	if len(ids) == 0 {
		t.Fatalf("no identities discovered from ssh_config")
	}
	found := false
	for _, id := range ids {
		if strings.Contains(id.Source, "id_ed25519_test") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected identity from ssh_config, got %v", ids)
	}
}
