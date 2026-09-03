package sshconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTmp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParse_BasicHost(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTmp(t, dir, "config", `
Host ops
    HostName 212.41.10.153
    User root
    Port 2200
    IdentityFile ~/.ssh/id_ops
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if r.Hostname != "212.41.10.153" {
		t.Errorf("hostname = %q", r.Hostname)
	}
	if r.User != "root" {
		t.Errorf("user = %q", r.User)
	}
	if r.Port != 2200 {
		t.Errorf("port = %d", r.Port)
	}
	if len(r.IdentityFiles) != 1 {
		t.Errorf("identity files = %v", r.IdentityFiles)
	}
}

func TestParse_FirstWins(t *testing.T) {
	// В OpenSSH: первое значение побеждает. Host * после специфичного
	// блока НЕ должен перекрывать User.
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops
    User opsuser

Host *
    User defaultuser
    Port 22
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if r.User != "opsuser" {
		t.Errorf("user = %q, want opsuser", r.User)
	}
	if r.Port != 22 {
		t.Errorf("port = %d, want 22 (from Host *)", r.Port)
	}
}

func TestParse_MultiplePatterns(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops ops2 *.prod.example.com !*.bad.example.com
    User infra

Host *.bad.example.com
    User blocked
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"ops", "ops2", "db.prod.example.com"} {
		if r := cfg.Resolve(alias); r.User != "infra" {
			t.Errorf("%s: user = %q, want infra", alias, r.User)
		}
	}
	if r := cfg.Resolve("evil.bad.example.com"); r.User != "blocked" {
		t.Errorf("negation: user = %q, want blocked", r.User)
	}
}

func TestParse_IdentityAccumulation(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops
    IdentityFile ~/.ssh/id_ops

Host *
    IdentityFile ~/.ssh/id_main
    IdentityFile ~/.ssh/id_fallback
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if len(r.IdentityFiles) != 3 {
		t.Fatalf("identity files = %v, want 3", r.IdentityFiles)
	}
	if filepath.Base(r.IdentityFiles[0]) != "id_ops" {
		t.Errorf("first identity = %q", r.IdentityFiles[0])
	}
}

func TestParse_IncludeRecursive(t *testing.T) {
	dir := t.TempDir()
	writeTmp(t, dir, "ssh/config.d/extra", `
Host extra
    User extrauser
`)
	writeTmp(t, dir, "ssh/config.d/more", `
Host more
    User moreuser
    Include sub/deeper
`)
	// OpenSSH: относительные Include — от базы пользовательского конфига
	// (dir/ssh), а не от каталога включающего файла.
	writeTmp(t, dir, "ssh/sub/deeper", `
Host deeper
    User deeperuser
`)
	cfgPath := writeTmp(t, dir, "ssh/config", `
Include config.d/*
Host main
    User mainuser
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for alias, wantUser := range map[string]string{
		"extra":  "extrauser",
		"more":   "moreuser",
		"deeper": "deeperuser",
		"main":   "mainuser",
	} {
		if r := cfg.Resolve(alias); r.User != wantUser {
			t.Errorf("%s: user = %q, want %q", alias, r.User, wantUser)
		}
	}
}

func TestParse_IncludeMissingGlobNotFatal(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTmp(t, dir, "config", `
Include config.d/*
Host main
    User mainuser
`)
	if _, err := Parse(cfgPath); err != nil {
		t.Fatalf("Include with no matches must not fail: %v", err)
	}
}

func TestParse_TokenExpansion(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTmp(t, dir, "config", `
Host ops
    HostName ops.internal
    User root
    IdentityFile ~/.ssh/%h_id
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if len(r.IdentityFiles) != 1 {
		t.Fatal("no identity files")
	}
	if !strings.HasSuffix(r.IdentityFiles[0], filepath.Join(".ssh", "ops.internal_id")) {
		t.Errorf("identity = %q, want .../ops.internal_id", r.IdentityFiles[0])
	}
}

func TestParse_MatchSkippedWithWarning(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops
    User before

Match host ops exec "true"
    User skipped

Host plain
    User plainuser
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected Match warning")
	}
	if r := cfg.Resolve("ops"); r.User != "before" {
		t.Errorf("ops user = %q, want before", r.User)
	}
	if r := cfg.Resolve("plain"); r.User != "plainuser" {
		t.Errorf("plain user = %q", r.User)
	}
}

func TestParse_QuotedValues(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops
    IdentityFile "~/.ssh/id key with space"
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if len(r.IdentityFiles) != 1 {
		t.Fatal("no identity")
	}
	if !strings.Contains(r.IdentityFiles[0], "id key with space") {
		t.Errorf("identity = %q, quotes not stripped", r.IdentityFiles[0])
	}
}

func TestParse_KeyEqualsValue(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops
    User=opsuser
    Port=2022
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if r.User != "opsuser" || r.Port != 2022 {
		t.Errorf("user/port = %q/%d", r.User, r.Port)
	}
}

func TestParse_PortAndHostnameInToken(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops
    HostName 10.0.0.1
    Port 2200
    IdentityFile ~/.ssh/id_%h_%p
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if !strings.Contains(r.IdentityFiles[0], "id_10.0.0.1_2200") {
		t.Errorf("identity = %q", r.IdentityFiles[0])
	}
}

func TestLoad_CascadeUserOverSystem(t *testing.T) {
	dir := t.TempDir()
	userCfg := writeTmp(t, dir, "user_config", `
Host ops
    User usercascade
`)
	sysCfg := writeTmp(t, dir, "system_config", `
Host ops
    User syscascade

Host *
    Port 22
`)
	cfg, err := Load(userCfg, sysCfg)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if r.User != "usercascade" {
		t.Errorf("user = %q, want usercascade", r.User)
	}
	if r.Port != 22 {
		t.Errorf("port = %d", r.Port)
	}
}

func TestLoad_IgnoreUnknownOptions(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
IgnoreUnknown UseKeychain

Host ops
    UseKeychain yes
    AddKeysToAgent yes
    User opsuser
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Resolve("ops")
	if r.User != "opsuser" {
		t.Errorf("user = %q", r.User)
	}
}

func TestHosts(t *testing.T) {
	cfgPath := writeTmp(t, t.TempDir(), "config", `
Host ops
Host ops2
Host *.example.com
Host !blocked
Host main
`)
	cfg, err := Parse(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	hosts := cfg.Hosts()
	got := map[string]bool{}
	for _, h := range hosts {
		got[h] = true
	}
	for _, want := range []string{"ops", "ops2", "main"} {
		if !got[want] {
			t.Errorf("hosts missing %q: %v", want, hosts)
		}
	}
	if got["*.example.com"] || got["!blocked"] {
		t.Errorf("hosts must not contain globs/negations: %v", hosts)
	}
}
