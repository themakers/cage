package libssh

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback строит check по known_hosts:
//
//   - "yes"        — строго из known_hosts, неизвестный хост = ошибка;
//   - "accept-new" — неизвестный хост дописывается в первый writable-known_hosts;
//   - "no"         — без проверки (как libgate, не рекомендуется).
//
// Mismatch (подмена ключа) всегда ошибка.
func hostKeyCallback(r resolved, lg *slog.Logger) (ssh.HostKeyCallback, error) {
	switch r.strictHostKey {
	case "no", "off", "false":
		lg.Warn("libssh: host key verification DISABLED for", "target", r.hostname)
		return ssh.InsecureIgnoreHostKey(), nil
	}

	// Собираем существующие файлы; несуществующие known_hosts пропускаем.
	var files []string
	for _, f := range r.knownHostsFiles {
		if _, err := os.Stat(f); err == nil {
			files = append(files, f)
		}
	}

	callbacks := make([]ssh.HostKeyCallback, 0, len(files))
	for _, f := range files {
		cb, err := knownhosts.New(f)
		if err != nil {
			lg.Debug("libssh: unusable known_hosts", "file", f, "err", err)
			continue
		}
		callbacks = append(callbacks, cb)
	}

	acceptNew := r.strictHostKey == "accept-new"

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// Проверяем всеми известными базами.
		var firstErr error
		for _, cb := range callbacks {
			err := cb(hostname, remote, key)
			if err == nil {
				return nil
			}
			var ke *knownhosts.KeyError
			if errors := asKeyError(err, &ke); errors && len(ke.Want) > 0 {
				// Ключ хоста известен и НЕ совпал — потенциальная подмена.
				return hostKeyMismatchError(r.alias, hostname, ke)
			}
			if firstErr == nil {
				firstErr = err
			}
		}

		// Ни одна база ключа не знает и не отвергла.
		if acceptNew {
			if err := addKnownHost(files, r.knownHostsFiles, hostname, key); err != nil {
				return fmt.Errorf("libssh: unknown host %s and failed to accept-new: %w", r.hostname, err)
			}
			lg.Info("libssh: added new host key", "target", r.hostname, "fingerprint", ssh.FingerprintSHA256(key))
			return nil
		}
		if firstErr != nil {
			return fmt.Errorf("libssh: host key verification failed for %s: %w", r.hostname, firstErr)
		}
		return fmt.Errorf("libssh: host %s not in known_hosts (strict checking)", r.hostname)
	}, nil
}

// asKeyError — errors.As адаптер (knownhosts.KeyError — указательный тип).
func asKeyError(err error, target **knownhosts.KeyError) bool {
	var ke *knownhosts.KeyError
	if errors.As(err, &ke) {
		*target = ke
		return true
	}
	return false
}

func hostKeyMismatchError(alias, hostname string, ke *knownhosts.KeyError) error {
	return fmt.Errorf(
		"libssh: HOST KEY MISMATCH for %s — ключ не совпадает с known_hosts (возможна подмена). "+
			"Проверьте fingerprint вручную и очистите устаревшую запись: ssh-keygen -F %s / ssh-keygen -R %s",
		alias, hostname, hostname,
	)
}

// addKnownHost дописывает ключ в первый (самый приоритетный — user)
// writable known_hosts из списка.
func addKnownHost(existing, configured []string, hostname string, key ssh.PublicKey) error {
	line := knownhosts.Line([]string{hostname}, key)
	targets := existing
	if len(targets) == 0 {
		targets = configured
	}
	for _, f := range targets {
		if err := appendFile0600(f, line+"\n"); err == nil {
			return nil
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no known_hosts files configured")
	}
	return fmt.Errorf("no writable known_hosts among %v", targets)
}

func appendFile0600(path, s string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(s)
	return err
}
