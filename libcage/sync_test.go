package libcage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two working copies of one repository: alice and bob. pull copies the
// store (what `git pull` does); the plaintext and .cage/local stay.

type team struct {
	t            *testing.T
	alice, bob   testKey
	aliceC, bobC *Cage
}

func newTeam(t *testing.T) *team {
	alice, bob := newTestKey(t), newTestKey(t)
	tm := &team{t: t, alice: alice, bob: bob}
	tm.aliceC = newTestCage(t, alice, bob, alice)
	tm.bobC = newTestCage(t, alice, bob, bob)
	return tm
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.RemoveAll(dst); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(out, 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// pull: dst gets src's store.
func pull(t *testing.T, src, dst *Cage) {
	t.Helper()
	copyTree(t, src.StoreDir(), dst.StoreDir())
}

func read(t *testing.T, c *Cage, ref string) string {
	t.Helper()
	r, _ := ParseSecretRef(ref)
	p, _ := c.PlaintextPath(r)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected error containing %q, got %v", contains, err)
	}
}

func state(t *testing.T, c *Cage, ref string) SyncState {
	t.Helper()
	r, _ := ParseSecretRef(ref)
	in, err := c.syncState(r)
	mustOK(t, err)
	return in.State
}

// start: alice publishes a.env and b.env, bob pulls and decrypts.
func (tm *team) start(a, b string) {
	t := tm.t
	writePlain(t, tm.aliceC, "a.env", a)
	writePlain(t, tm.aliceC, "b.env", b)
	writePlain(t, tm.aliceC, "bob:own.env", "OWN=1\n")
	mustOK(t, tm.aliceC.EncryptAll())
	pull(t, tm.aliceC, tm.bobC)
	mustOK(t, tm.bobC.DecryptAll())
}

func TestPullKeepsLocalChangesAndUpdatesUnchanged(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\nY=1\n", "B=1\n")

	writePlain(t, tm.aliceC, "a.env", "X=2\nY=1\n")
	mustOK(t, tm.aliceC.EncryptAll())
	writePlain(t, tm.bobC, "b.env", "B=2\n") // bob's unpublished change

	pull(t, tm.aliceC, tm.bobC)
	if s := state(t, tm.bobC, "a.env"); s != SyncOutdated {
		t.Fatalf("a.env: %s", s)
	}
	//> The bug being fixed: encrypt before decrypt silently reverted alice.
	mustErr(t, tm.bobC.EncryptAll(), "run `cage decrypt` first")

	mustOK(t, tm.bobC.DecryptAll())
	if got := read(t, tm.bobC, "a.env"); got != "X=2\nY=1\n" {
		t.Fatalf("a.env not updated: %q", got)
	}
	if got := read(t, tm.bobC, "b.env"); got != "B=2\n" {
		t.Fatalf("local change lost: %q", got)
	}
	mustOK(t, tm.bobC.EncryptAll())

	pull(t, tm.bobC, tm.aliceC)
	mustOK(t, tm.aliceC.DecryptAll())
	if read(t, tm.aliceC, "b.env") != "B=2\n" || read(t, tm.aliceC, "a.env") != "X=2\nY=1\n" {
		t.Fatal("alice did not get both changes")
	}
}

func TestMergeBothChanged(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\nY=1\nZ=1\n", "B=1\n")

	writePlain(t, tm.aliceC, "a.env", "X=2\nY=1\nZ=1\n")
	mustOK(t, tm.aliceC.EncryptAll())
	writePlain(t, tm.bobC, "a.env", "X=1\nY=1\nZ=2\n")

	pull(t, tm.aliceC, tm.bobC)
	mustOK(t, tm.bobC.DecryptAll())
	if got := read(t, tm.bobC, "a.env"); got != "X=2\nY=1\nZ=2\n" {
		t.Fatalf("merge: %q", got)
	}
	if s := state(t, tm.bobC, "a.env"); s != SyncModified {
		t.Fatalf("after merge: %s", s)
	}
	mustOK(t, tm.bobC.EncryptAll())
	s, _ := tm.bobC.readStoreVersion(SecretRef{Dir: "default", Name: "a.env"})
	if len(s.History) != 2 {
		t.Fatalf("history: %v", s.History)
	}
}

// Both encrypted the same secret; git conflict in the store file resolved by
// taking alice's file: bob's change must survive (merged via the previous
// base, the common ancestor).
func TestBothEncryptedSameSecret(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\nY=1\nZ=1\n", "B=1\n")

	writePlain(t, tm.aliceC, "a.env", "X=2\nY=1\nZ=1\n")
	mustOK(t, tm.aliceC.EncryptAll())
	writePlain(t, tm.bobC, "a.env", "X=1\nY=1\nZ=2\n")
	mustOK(t, tm.bobC.EncryptAll())

	pull(t, tm.aliceC, tm.bobC) // git checkout --theirs
	mustOK(t, tm.bobC.DecryptAll())
	if got := read(t, tm.bobC, "a.env"); got != "X=2\nY=1\nZ=2\n" {
		t.Fatalf("bob's change lost or not merged: %q", got)
	}
}

func TestConflictMarkersAndResolve(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\nY=1\n", "B=1\n")

	writePlain(t, tm.aliceC, "a.env", "X=2\nY=1\n")
	mustOK(t, tm.aliceC.EncryptAll())
	writePlain(t, tm.bobC, "a.env", "X=3\nY=1\n")
	writePlain(t, tm.bobC, "b.env", "B=1\nC=1\n")

	pull(t, tm.aliceC, tm.bobC)
	err := tm.bobC.DecryptAll()
	mustErr(t, err, "conflict in X")
	if strings.Contains(err.Error(), "=2") || strings.Contains(err.Error(), "=3") {
		t.Fatalf("values leaked: %v", err)
	}
	want := "<<<<<<< local\nX=3\n=======\nX=2\n>>>>>>> store\nY=1\n"
	if got := read(t, tm.bobC, "a.env"); got != want {
		t.Fatalf("markers:\n%s", got)
	}
	if read(t, tm.bobC, "b.env") != "B=1\nC=1\n" {
		t.Fatal("other secrets must be processed")
	}
	mustErr(t, tm.bobC.EncryptAll(), "unresolved conflict")
	_, err = tm.bobC.ReadPlainForEdit(SecretRef{Dir: "default", Name: "a.env"})
	mustErr(t, err, "unresolved conflict")

	mustOK(t, tm.bobC.Resolve(SecretRef{Dir: "default", Name: "a.env"}, true))
	if got := read(t, tm.bobC, "a.env"); got != "X=3\nY=1\n" {
		t.Fatalf("resolve -local: %q", got)
	}
	mustOK(t, tm.bobC.EncryptAll())
}

// Store goes back to an older version (revert, branch switch): not applied
// silently.
func TestStoreOlderThanBase(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\n", "B=1\n")
	old := t.TempDir()
	copyTree(t, tm.bobC.StoreDir(), old)

	writePlain(t, tm.bobC, "a.env", "X=2\n")
	mustOK(t, tm.bobC.EncryptAll())
	copyTree(t, old, tm.bobC.StoreDir()) // git revert

	in, err := tm.bobC.syncState(SecretRef{Dir: "default", Name: "a.env"})
	mustOK(t, err)
	if in.State != SyncDiverged || !in.Older {
		t.Fatalf("state %s older %v", in.State, in.Older)
	}
	mustErr(t, tm.bobC.DecryptAll(), "store is older")
	mustOK(t, tm.bobC.Resolve(SecretRef{Dir: "default", Name: "a.env"}, false))
	if read(t, tm.bobC, "a.env") != "X=1\n" {
		t.Fatal("resolve -store")
	}
}

func TestFirstRunWithoutBase(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\nY=1\n", "B=1\n")
	mustOK(t, os.RemoveAll(tm.bobC.LocalDir()))
	writePlain(t, tm.bobC, "a.env", "X=1\nY=2\n")

	if s := state(t, tm.bobC, "b.env"); s != SyncInSync {
		t.Fatalf("b.env: %s", s)
	}
	mustErr(t, tm.bobC.DecryptAll(), "no common base")
	if got := read(t, tm.bobC, "a.env"); got != "X=1\n<<<<<<< local\nY=2\n=======\nY=1\n>>>>>>> store\n" {
		t.Fatalf("two-way markers:\n%s", got)
	}
}

func TestStoreIntegrity(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\n", "B=1\n")
	sp, _ := tm.bobC.StoreSecretPath(SecretRef{Dir: "default", Name: "a.env"})
	b, _ := os.ReadFile(sp)

	bad := strings.Replace(string(b), "plaintext_sha256: ", "plaintext_sha256: 00", 1)
	mustOK(t, os.WriteFile(sp, []byte(bad), 0o600))
	_, err := tm.bobC.ReadSecretPlainPreferStore(SecretRef{Dir: "default", Name: "a.env"})
	mustErr(t, err, "corrupted")

	conflicted := "<<<<<<< HEAD\n" + string(b) + "=======\n" + string(b) + ">>>>>>> theirs\n"
	mustOK(t, os.WriteFile(sp, []byte(conflicted), 0o600))
	mustErr(t, tm.bobC.DecryptAll(), "git checkout --theirs")
}

func TestBinarySecretConflict(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\n", "B=1\n")
	ref := SecretRef{Dir: "default", Name: "b.env"}
	writePlain(t, tm.aliceC, "b.env", "B=\x00alice\n")
	mustOK(t, tm.aliceC.EncryptAll())
	writePlain(t, tm.bobC, "b.env", "B=\x00bob\n")
	pull(t, tm.aliceC, tm.bobC)
	mustErr(t, tm.bobC.DecryptAll(), "binary secret")
	mustOK(t, tm.bobC.Resolve(ref, false))
	if read(t, tm.bobC, "b.env") != "B=\x00alice\n" {
		t.Fatal("resolve -store for binary")
	}
}

func TestRemovedSecret(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\n", "B=1\n")
	cfgPath := tm.bobC.ConfigPath()
	b, _ := os.ReadFile(cfgPath)
	mustOK(t, os.WriteFile(cfgPath, []byte(strings.Replace(string(b), "[a.env, b.env]", "[b.env]", 1)), 0o600))
	bob := openTestCage(t, tm.bobC.Root, tm.bob)

	mustOK(t, bob.DecryptAll())
	if _, err := os.Stat(filepath.Join(bob.Root, ".cage/secrets/a.env")); !os.IsNotExist(err) {
		t.Fatal("unchanged removed secret must be deleted")
	}

	// Removed with local changes: kept and reported.
	mustOK(t, os.WriteFile(cfgPath, b, 0o600))
	bob = openTestCage(t, tm.bobC.Root, tm.bob)
	mustOK(t, bob.DecryptAll())
	writePlain(t, bob, "a.env", "X=9\n")
	mustOK(t, os.WriteFile(cfgPath, []byte(strings.Replace(string(b), "[a.env, b.env]", "[b.env]", 1)), 0o600))
	bob = openTestCage(t, tm.bobC.Root, tm.bob)
	mustErr(t, bob.DecryptAll(), "unpublished local changes")
	if read(t, bob, "a.env") != "X=9\n" {
		t.Fatal("local change lost")
	}
}

func TestGitignoreAndDirsValidation(t *testing.T) {
	tm := newTeam(t)
	tm.start("X=1\n", "B=1\n")
	b, err := os.ReadFile(filepath.Join(tm.bobC.CageDir(), ".gitignore"))
	mustOK(t, err)
	if string(b) != gitignoreHeader+"/local/\n/secrets/\n" {
		t.Fatalf(".gitignore:\n%s", b)
	}
	for _, bad := range []string{"secrets", "../x", ".cage/store/x", ".cage/local", "/abs/.cage/x"} {
		if _, err := plaintextDirInCage(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestMerge3(t *testing.T) {
	cases := []struct{ base, local, store, want string }{
		//> Adjacent changes conflict, as in git; separated ones merge.
		{"a\nb\nc\nd\n", "a\nB\nc\nd\n", "a\nb\nc\nD\n", "a\nB\nc\nD\n"},
		{"a\nb\n", "a\nb\nx\n", "y\na\nb\n", "y\na\nb\nx\n"},
		{"a\nb\n", "a\n", "a\nb\n", "a\n"},
		{"a\n", "a\n", "", ""},
	}
	for _, c := range cases {
		res := merge3([]byte(c.base), []byte(c.local), []byte(c.store))
		if string(res.Text) != c.want || len(res.Conflicts) != 0 {
			t.Fatalf("merge3(%q,%q,%q) = %q conflicts %d", c.base, c.local, c.store, res.Text, len(res.Conflicts))
		}
	}
}
