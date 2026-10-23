package libcage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	agessh "filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

// LoadIdentityFile loads exactly one SSH private key for unattended
// decryption (machine identities). Unlike DiscoverIdentities it never falls
// back to other keys: a service must decrypt with the identity it was
// configured with or fail. The key must not be accessible to group/others.
func LoadIdentityFile(path string) (Identities, error) {
	if !filepath.IsAbs(path) {
		return Identities{}, fmt.Errorf("identity %s: path must be absolute", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return Identities{}, fmt.Errorf("identity %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return Identities{}, fmt.Errorf("identity %s: not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return Identities{}, fmt.Errorf("identity %s: must not be accessible by group or others (mode %04o)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Identities{}, fmt.Errorf("identity %s: %w", path, err)
	}
	defer clear(b)
	ident, err := agessh.ParseIdentity(b)
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return Identities{}, fmt.Errorf("identity %s: passphrase-protected keys cannot be used for unattended decryption", path)
		}
		return Identities{}, fmt.Errorf("identity %s: unsupported or invalid SSH private key", path)
	}
	return Identities{SSH: []SSHIdentity{{
		Identity:    ident,
		Source:      "identity-file:" + filepath.Base(path),
		Fingerprint: fingerprintFromPubFileIfExists(path + ".pub"),
		PublicKey:   keyPublic(b, path),
	}}}, nil
}
