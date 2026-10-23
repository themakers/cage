//go:build !linux

package libcage

import "errors"

var errCredentialsUnsupported = errors.New("service credentials are supported only on Linux (systemd)")

func HardenCredentialsProcess() error { return errCredentialsUnsupported }

func PublishCredentials(*CredentialsManifest, map[string][]byte) error {
	return errCredentialsUnsupported
}

func CleanCredentials(*CredentialsManifest) error { return errCredentialsUnsupported }
