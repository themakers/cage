package libcage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

type testKey struct {
	pub string
	id  SSHIdentity
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	ident, err := agessh.ParseIdentity(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	pub := publicKeyFromPrivate(pemBytes)
	return testKey{pub: pub, id: SSHIdentity{Identity: ident, Source: "test", PublicKey: pub}}
}

// newTestCage: root with dirs default/ and bob/; env "shared" (alice+bob)
// and "bob-only" (bob).
func newTestCage(t *testing.T, alice, bob testKey, as testKey) *Cage {
	t.Helper()
	root := t.TempDir()
	cfg := `kind: cage/v1
dirs:
  default: .cage/secrets
  bob: .cage/secrets/bob
recipients:
  alice:
    - ` + alice.pub + `
  bob:
    - ` + bob.pub + `
  devs:
    - alice
    - bob
envs:
  shared:
    files: [a.env, b.env]
    recipients: [devs]
  bob-only:
    files: ["bob:own.env"]
    recipients: [bob]
`
	for _, d := range []string{".cage/secrets/bob"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".cage", "cage.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return openTestCage(t, root, as)
}

func openTestCage(t *testing.T, root string, as testKey) *Cage {
	t.Helper()
	c, err := New(NewOptions{
		Root:       root,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Identities: &Identities{SSH: []SSHIdentity{as.id}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writePlain(t *testing.T, c *Cage, ref, body string) {
	t.Helper()
	r, err := ParseSecretRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WritePlain(r, []byte(body)); err != nil {
		t.Fatal(err)
	}
}

func TestDecryptAllSkipsSecretsOfOtherRecipients(t *testing.T) {
	alice, bob := newTestKey(t), newTestKey(t)
	cb := newTestCage(t, alice, bob, bob)
	writePlain(t, cb, "a.env", "A=1\n")
	writePlain(t, cb, "b.env", "B=2\n")
	writePlain(t, cb, "bob:own.env", "OWN=secret-of-bob\n")
	if err := cb.EncryptAll(); err != nil {
		t.Fatal(err)
	}
	// Alice gets the repository without plaintext.
	if err := os.RemoveAll(filepath.Join(cb.Root, ".cage", "secrets")); err != nil {
		t.Fatal(err)
	}
	ca := openTestCage(t, cb.Root, alice)
	if err := ca.DecryptAll(); err != nil {
		t.Fatalf("decrypt must skip bob's secret: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cb.Root, ".cage/secrets/a.env")); err != nil {
		t.Fatalf("shared secret not decrypted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cb.Root, ".cage/secrets/bob/own.env")); !os.IsNotExist(err) {
		t.Fatalf("bob's secret must not be decrypted for alice")
	}
	// Encrypt without bob's plaintext keeps his secret intact.
	if err := ca.EncryptAll(); err != nil {
		t.Fatal(err)
	}
	who, err := ca.Whoami()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(who.Names, ",") != "alice" || strings.Join(who.Groups, ",") != "devs" {
		t.Fatalf("whoami: %+v", who)
	}
}

func TestEnvCollisionsAndPrefix(t *testing.T) {
	alice, bob := newTestKey(t), newTestKey(t)
	c := newTestCage(t, alice, bob, alice)
	writePlain(t, c, "a.env", "USER=a\nPASSWORD=pa")       // no trailing newline
	writePlain(t, c, "b.env", "USER=b\nPASSWORD='p b'\n") // same names

	if _, err := c.BuildEnv([]string{"a.env", "b.env"}, false); err == nil || !strings.Contains(err.Error(), "defined by both") {
		t.Fatalf("expected collision error, got %v", err)
	}
	var out bytes.Buffer
	if err := c.Dump([]string{"a.env", "b.env"}, &out); err == nil {
		t.Fatalf("dump must reject collisions")
	}

	vars, err := c.BuildEnvVars([]string{"A_=a.env", "B_=b.env"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if vars["A_USER"] != "a" || vars["B_PASSWORD"] != "p b" {
		t.Fatalf("prefix: %v", vars)
	}
	out.Reset()
	if err := c.Dump([]string{"A_=a.env", "B_=b.env"}, &out); err != nil {
		t.Fatal(err)
	}
	got, err := ParseDotenv(out.Bytes())
	if err != nil || got["A_PASSWORD"] != "pa" || got["B_PASSWORD"] != "p b" {
		t.Fatalf("prefixed dump: %v %v\n%s", got, err, out.String())
	}

	writePlain(t, c, "b.env", "OTHER=x\n")
	out.Reset()
	if err := c.Dump([]string{"a.env", "b.env"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PASSWORD=pa\nOTHER=x\n") {
		t.Fatalf("files must be separated by a newline:\n%q", out.String())
	}
}

func TestMaskWriterAcrossWrites(t *testing.T) {
	pats := MaskPatterns([]string{"s3cr3t-value-123", "dev", "mongodb://u:hunter2pass@h:27017/db", "https://storage.example.com"})
	var out bytes.Buffer
	w := NewMaskWriter(&out, pats)
	for _, chunk := range []string{"token=s3cr3", "t-value-123; env=dev; pw=hunter2", "pass; ep=https://storage.example.com; tail s3cr"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	want := "token=" + MaskMarker + "; env=dev; pw=" + MaskMarker + "; ep=https://storage.example.com; tail s3cr"
	if out.String() != want {
		t.Fatalf("got  %q\nwant %q", out.String(), want)
	}
}

func TestDotenvEditPreservesFileAndRejectsMask(t *testing.T) {
	src := "# header\nA=1\n\n# about B\nB = two words\n#C=old\nexport D=\"d\"\n"
	f := ParseDotenvFile([]byte(src))
	if v, ok, err := f.Get("B"); err != nil || !ok || v != "two words" {
		t.Fatalf("B: %q %v %v", v, ok, err)
	}
	if err := f.Set("A", "new value"); err != nil {
		t.Fatal(err)
	}
	if err := f.Enable("C"); err != nil {
		t.Fatal(err)
	}
	if err := f.Annotate("D", "dee"); err != nil {
		t.Fatal(err)
	}
	f.Remove("B")
	want := "# header\nA='new value'\n\n# about B\nC=old\n# dee\nexport D=\"d\"\n"
	if string(f.Bytes()) != want {
		t.Fatalf("got\n%s\nwant\n%s", f.Bytes(), want)
	}
	if err := f.Set("X", "a"+MaskMarker); err == nil {
		t.Fatalf("mask marker must be rejected")
	}
}

func TestInspectFindsDuplicatesWithoutValues(t *testing.T) {
	alice, bob := newTestKey(t), newTestKey(t)
	c := newTestCage(t, alice, bob, alice)
	writePlain(t, c, "a.env", "# the key\nKEY=topsecret-123456\nURI=mongodb://u:passw0rd-xyz@h1,h2/db?replicaSet=rs&authSource=admin\n")
	writePlain(t, c, "b.env", "#OLD = topsecret-123456\nPW=passw0rd-xyz\n")
	rep, err := c.Inspect(nil)
	if err != nil {
		t.Fatal(err)
	}
	var dump bytes.Buffer
	for _, f := range rep.Files {
		dump.WriteString(f.Ref)
		for _, v := range f.Vars {
			dump.WriteString(" " + v.Key + strings.Join(v.Dups, "|"))
			if v.URI != nil {
				dump.WriteString(" uri:" + strings.Join(v.URI.Hosts, ",") + strings.Join(v.URI.PasswordDups, "|"))
			}
		}
		dump.WriteString("\n")
	}
	s := dump.String()
	for _, want := range []string{"KEYb.env:OLD", "OLDa.env:KEY", "uri:h1,h2b.env:PW", "PWa.env:URI#password"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if strings.Contains(s, "topsecret") || strings.Contains(s, "passw0rd") {
		t.Fatalf("values leaked:\n%s", s)
	}
}
