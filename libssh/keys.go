package libssh

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// LoadIdentityFile парсит приватный ключ (OpenSSH / PEM). Поддерживаются
// незашифрованные ключи; passphrase-protected и FIDO/U2F (sk-*) ключи
// дают ясную ошибку с указанием добавить ключ в ssh-agent.
func LoadIdentityFile(path string) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err == nil {
		return signer, nil
	}

	var pmErr *ssh.PassphraseMissingError
	if errors.As(err, &pmErr) || strings.Contains(err.Error(), "passphrase protected") || strings.Contains(err.Error(), "cannot decode encrypted") {
		return nil, fmt.Errorf("key %s is passphrase-protected; add it to ssh-agent (ssh-add %s) or remove passphrase", path, path)
	}
	if strings.Contains(string(b), "sk-ssh-ed25519@openssh.com") || strings.Contains(string(b), "sk-ecdsa-sha2-nistp256@openssh.com") ||
		strings.Contains(err.Error(), "unhandled key type") {
		return nil, fmt.Errorf("key %s is a FIDO/U2F (sk-*) or unsupported key; add it to ssh-agent (ssh-add %s)", path, path)
	}
	return nil, fmt.Errorf("parse %s: %w", path, err)
}
