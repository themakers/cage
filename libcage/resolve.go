package libcage

import (
	"fmt"
	"os"
)

// Resolve settles a conflict left by decrypt: in every conflict chunk keep
// the local or the store side; for binary secrets keep the local file or
// take the store version (<name>.store). The base already is the store
// version, so the result is an ordinary local change (or in-sync).
func (c *Cage) Resolve(ref SecretRef, keepLocal bool) error {
	in, err := c.syncState(ref)
	if err != nil {
		return err
	}
	switch in.State {
	case SyncConflict:
	case SyncOutdated, SyncDiverged:
		return fmt.Errorf("%s: not merged yet — run `cage decrypt` first", ref)
	default:
		return fmt.Errorf("%s: no conflict (%s)", ref, in.State)
	}

	sidecar, err := c.storeSidecar(ref)
	if err != nil {
		return err
	}
	if store, ok, err := ReadFileIfExists(sidecar); err != nil {
		return err
	} else if ok {
		if !keepLocal {
			if err := c.WritePlain(ref, store); err != nil {
				return err
			}
		}
		return os.Remove(sidecar)
	}

	out, err := resolveMarkers(in.Plain, keepLocal)
	if err != nil {
		return fmt.Errorf("%s: %w — fix the markers by hand", ref, err)
	}
	if IsEnvSecretName(ref.Name) {
		if _, err := ParseDotenv(out); err != nil {
			return fmt.Errorf("%s: result does not parse (%v) — fix the file by hand", ref, err)
		}
	}
	return c.WritePlain(ref, out)
}
