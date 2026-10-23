//go:build linux

package libcage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ramfsMagic is RAMFS_MAGIC from linux/magic.h: ramfs pages are never
// swapped out (unlike tmpfs without noswap).
const ramfsMagic = 0x858458f6

// requireRamfs is disabled only by tests (unprivileged, cannot mount ramfs).
var requireRamfs = true

// HardenCredentialsProcess makes the current process non-dumpable: no core
// dumps and no ptrace or /proc/<pid>/mem access by unprivileged processes.
func HardenCredentialsProcess() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", errno)
	}
	return nil
}

// checkStagingDir requires a root-owned directory inaccessible to others on
// ramfs, so that plaintext is neither swappable nor reachable by consumers.
func checkStagingDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("staging dir %s: %w", dir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("staging dir %s: not a directory", dir)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("staging dir %s: must be owned by the preparer (uid %d)", dir, os.Geteuid())
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("staging dir %s: must not be accessible by group or others (mode %04o)", dir, st.Mode().Perm())
	}
	if !requireRamfs {
		return nil
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(dir, &fs); err != nil {
		return fmt.Errorf("staging dir %s: statfs: %w", dir, err)
	}
	if uint64(fs.Type) != ramfsMagic {
		return fmt.Errorf("staging dir %s: must be on ramfs (non-swappable), filesystem type is %#x", dir, uint64(fs.Type))
	}
	return nil
}

// PublishCredentials atomically publishes the complete set as
// <stagingDir>/<unit>/<name>: files are written into a fresh private
// directory (O_EXCL|O_NOFOLLOW, 0600) which is then renamed into place.
// A previously published set is removed first, so a failure never leaves
// a stale or partial set behind.
func PublishCredentials(m *CredentialsManifest, creds map[string][]byte) error {
	if err := checkStagingDir(m.StagingDir); err != nil {
		return err
	}
	if err := CleanCredentials(m); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(m.StagingDir, tmpPrefix(m))
	if err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(tmp)
		}
	}()
	for _, c := range m.Credentials {
		if len(creds[c.Name]) == 0 {
			return fmt.Errorf("credential %s: missing or empty", c.Name)
		}
		if err := writeCredentialFile(filepath.Join(tmp, c.Name), creds[c.Name]); err != nil {
			return fmt.Errorf("credential %s: %w", c.Name, err)
		}
	}
	if err := os.Rename(tmp, m.CredentialsTarget()); err != nil {
		return fmt.Errorf("staging: publish: %w", err)
	}
	ok = true
	return nil
}

func writeCredentialFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// CleanCredentials removes the published set and leftovers of interrupted
// publications. It is idempotent.
func CleanCredentials(m *CredentialsManifest) error {
	if err := checkStagingDir(m.StagingDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.RemoveAll(m.CredentialsTarget()); err != nil {
		return fmt.Errorf("staging: clean: %w", err)
	}
	entries, err := os.ReadDir(m.StagingDir)
	if err != nil {
		return fmt.Errorf("staging: clean: %w", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), tmpPrefix(m)) {
			if err := os.RemoveAll(filepath.Join(m.StagingDir, e.Name())); err != nil {
				return fmt.Errorf("staging: clean: %w", err)
			}
		}
	}
	return nil
}

// tmpPrefix names in-progress publications; '#' cannot occur in unit names,
// so prefixes of different units never overlap.
func tmpPrefix(m *CredentialsManifest) string {
	return "." + m.Unit + "#"
}
