package libcage

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"

	"github.com/themakers/cage/libssh/sshconfig"
)

type SSHIdentity struct {
	Identity    age.Identity
	Source      string // human-readable
	Fingerprint string // optional
}

type Identities struct {
	SSH []SSHIdentity
}

func (ids Identities) Age() []age.Identity {
	out := make([]age.Identity, 0, len(ids.SSH))
	for _, id := range ids.SSH {
		if id.Identity != nil {
			out = append(out, id.Identity)
		}
	}
	return out
}

func (ids Identities) Empty() bool {
	return len(ids.Age()) == 0
}

type DiscoverOptions struct {
	Logger *slog.Logger
}

func DiscoverIdentities(opts DiscoverOptions) (Identities, error) {
	lg := opts.Logger
	if lg == nil {
		lg = slog.Default()
	}
	var out Identities
	seen := map[string]struct{}{}

	add := func(id SSHIdentity) {
		key := id.Fingerprint
		if key == "" {
			key = id.Source
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out.SSH = append(out.SSH, id)
	}

	if id, ok := identityFromCAGEEnv(lg); ok {
		add(id)
	}

	cfgIds, err := identitiesFromSSHConfig(lg)
	if err != nil {
		lg.Debug("ssh config identities error", "err", err)
	}
	for _, id := range cfgIds {
		add(id)
	}

	stdIds, err := identitiesFromStandardSSHFiles(lg)
	if err != nil {
		lg.Debug("standard ssh identities error", "err", err)
	}
	for _, id := range stdIds {
		add(id)
	}

	scanIds, err := identitiesFromSSHDirScan(lg)
	if err != nil {
		lg.Debug("ssh dir scan identities error", "err", err)
	}
	for _, id := range scanIds {
		add(id)
	}

	// stable ordering: prefer explicit env first, then ~/.ssh/config, then std, then scan;
	// within each group, stable sort by Source.
	sort.SliceStable(out.SSH, func(i, j int) bool { return out.SSH[i].Source < out.SSH[j].Source })

	return out, nil
}

func identityFromCAGEEnv(lg *slog.Logger) (SSHIdentity, bool) {
	val := strings.TrimSpace(os.Getenv("CAGE_SSH_IDENTITY"))
	if val == "" {
		return SSHIdentity{}, false
	}

	if looksLikePrivateKeyPEM(val) {
		ident, err := agessh.ParseIdentity([]byte(val))
		if err != nil {
			lg.Warn("CAGE_SSH_IDENTITY looks like key text but parse failed", "err", err)
			return SSHIdentity{}, false
		}
		return SSHIdentity{Identity: ident, Source: "CAGE_SSH_IDENTITY(text)"}, true
	}

	home, _ := os.UserHomeDir()
	p := expandTilde(val, home)
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		lg.Warn("read CAGE_SSH_IDENTITY(path) failed", "path", p, "err", err)
		return SSHIdentity{}, false
	}
	ident, err := agessh.ParseIdentity(b)
	if err != nil {
		lg.Warn("parse CAGE_SSH_IDENTITY(path) failed", "path", p, "err", err)
		return SSHIdentity{}, false
	}
	fp := fingerprintFromPubFileIfExists(p + ".pub")
	return SSHIdentity{Identity: ident, Source: "CAGE_SSH_IDENTITY(path:" + filepath.Base(p) + ")", Fingerprint: fp}, true
}

func looksLikePrivateKeyPEM(s string) bool {
	return strings.Contains(s, "BEGIN") && strings.Contains(s, "PRIVATE KEY")
}

func identitiesFromSSHConfig(lg *slog.Logger) ([]SSHIdentity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cfgPath := filepath.Join(home, ".ssh", "config")
	if _, err := os.Stat(cfgPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	// Единый парсер: libssh/sshconfig — честная семантика OpenSSH,
	// включая Include, Host-паттерны и token expansion.
	cfg, err := sshconfig.Load(cfgPath)
	if err != nil {
		return nil, err
	}

	// IdentityFile накапливаются со всех Host-блоков; для discovery
	// сканируем alias всех явных хостов + wildcard. Раскрытие ~/ и
	// %%-токенов выполняет sshconfig.Resolve.
	aliases := append([]string{"*"}, cfg.Hosts()...)
	seen := map[string]struct{}{}
	var paths []string
	for _, alias := range aliases {
		for _, p := range cfg.Resolve(alias).IdentityFiles {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			paths = append(paths, p)
		}
	}

	var out []SSHIdentity
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			lg.Debug("read IdentityFile failed", "path", p, "err", err)
			continue
		}
		ident, err := agessh.ParseIdentity(b)
		if err != nil {
			lg.Debug("parse IdentityFile failed", "path", p, "err", err)
			continue
		}
		fp := fingerprintFromPubFileIfExists(p + ".pub")
		out = append(out, SSHIdentity{Identity: ident, Source: "~/.ssh/config:" + filepath.Base(p), Fingerprint: fp})
	}
	return out, nil
}

func identitiesFromStandardSSHFiles(lg *slog.Logger) ([]SSHIdentity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")
	cands := []string{"id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"}
	var out []SSHIdentity
	for _, name := range cands {
		p := filepath.Join(sshDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		ident, err := agessh.ParseIdentity(b)
		if err != nil {
			lg.Debug("parse standard identity failed", "path", p, "err", err)
			continue
		}
		fp := fingerprintFromPubFileIfExists(p + ".pub")
		out = append(out, SSHIdentity{Identity: ident, Source: "~/.ssh/" + name, Fingerprint: fp})
	}
	return out, nil
}

func identitiesFromSSHDirScan(lg *slog.Logger) ([]SSHIdentity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")
	d, err := os.ReadDir(sshDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []SSHIdentity
	for _, ent := range d {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if strings.HasSuffix(name, ".pub") || strings.HasSuffix(name, ".pem") {
			continue
		}
		if !strings.HasPrefix(name, "id_") {
			continue
		}
		p := filepath.Join(sshDir, name)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		ident, err := agessh.ParseIdentity(b)
		if err != nil {
			continue
		}
		fp := fingerprintFromPubFileIfExists(p + ".pub")
		out = append(out, SSHIdentity{Identity: ident, Source: "~/.ssh(scan):" + name, Fingerprint: fp})
	}
	return out, nil
}

func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func fingerprintFromPubFileIfExists(pubPath string) string {
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

func (id SSHIdentity) Describe() string {
	if id.Fingerprint != "" {
		return fmt.Sprintf("%s (%s)", id.Source, id.Fingerprint)
	}
	return id.Source
}
