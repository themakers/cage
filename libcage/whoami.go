package libcage

import (
	"errors"
	"os"
	"sort"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"
)

// publicKeyFromPrivate derives the authorized-key form ("type base64") of a
// private key. Passphrase-protected keys still expose their public part.
func publicKeyFromPrivate(pemBytes []byte) string {
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err == nil {
		return normalizeKeyLine(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) && missing.PublicKey != nil {
		return normalizeKeyLine(string(ssh.MarshalAuthorizedKey(missing.PublicKey)))
	}
	return ""
}

func publicKeyFromPubFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return ""
	}
	return normalizeKeyLine(string(ssh.MarshalAuthorizedKey(pub)))
}

// normalizeKeyLine keeps "type base64" and drops the comment.
func normalizeKeyLine(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return ""
	}
	return f[0] + " " + f[1]
}

// PublicKeys returns the authorized-key forms of the discovered identities.
func (ids Identities) PublicKeys() []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids.SSH {
		if id.PublicKey == "" || seen[id.PublicKey] {
			continue
		}
		seen[id.PublicKey] = true
		out = append(out, id.PublicKey)
	}
	sort.Strings(out)
	return out
}

// WhoamiResult — recipients of cage.yaml that the current identities are.
type WhoamiResult struct {
	// Names lists recipient entries that contain one of the keys directly.
	Names []string `json:"names"`
	// Groups lists recipient entries that include one of the keys through
	// other entries.
	Groups []string `json:"groups"`
	// Keys are the public keys of the discovered identities.
	Keys []string `json:"keys"`
}

// Whoami maps the discovered identities to recipient names of cage.yaml.
func (c *Cage) Whoami() (WhoamiResult, error) {
	res := WhoamiResult{Keys: c.Ids.PublicKeys()}
	if c.Cfg == nil {
		return res, nil
	}
	mine := map[string]bool{}
	for _, k := range res.Keys {
		mine[k] = true
	}
	for name, vals := range c.Cfg.Recipients {
		direct := false
		for _, v := range vals {
			if LooksLikeSSHPublicKeyLine(v) && mine[normalizeKeyLine(v)] {
				direct = true
				break
			}
		}
		if direct {
			res.Names = append(res.Names, name)
			continue
		}
		keys, err := ResolveRecipientRefs(c.Cfg, []string{name})
		if err != nil {
			return WhoamiResult{}, err
		}
		for _, k := range keys {
			if mine[normalizeKeyLine(k)] {
				res.Groups = append(res.Groups, name)
				break
			}
		}
	}
	sort.Strings(res.Names)
	sort.Strings(res.Groups)
	return res, nil
}

// isNotRecipient reports whether decryption failed only because none of the
// identities is a recipient of the payload.
func isNotRecipient(err error) bool {
	var nm *age.NoIdentityMatchError
	return errors.As(err, &nm)
}
