package libcage

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

func ParseRecipients(sshPublicKeys []string) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, s := range sshPublicKeys {
		r, err := agessh.ParseRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("parse recipient %q: %w", s, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no recipients")
	}
	return out, nil
}

func EncryptBytes(plaintext []byte, recipients ...age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DecryptBytes(ciphertext []byte, identities ...age.Identity) ([]byte, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities")
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), identities...)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
