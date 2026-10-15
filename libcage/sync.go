package libcage

import (
	"fmt"
	"os"
)

// SyncState — relation of a working copy's plaintext (L) to the store file
// (S) through the base (B): the store version L was last synchronized with.
type SyncState string

const (
	SyncInSync    SyncState = "in-sync"    // L = S
	SyncModified  SyncState = "modified"   // L changed locally, store unchanged
	SyncOutdated  SyncState = "outdated"   // store is newer, L unchanged
	SyncDiverged  SyncState = "diverged"   // both changed (or unknown base): decrypt merges
	SyncConflict  SyncState = "conflict"   // L has unresolved conflict markers (or a .store sidecar)
	SyncNew       SyncState = "new"        // no plaintext yet
	SyncLocalOnly SyncState = "local-only" // no store file yet
	SyncMissing   SyncState = "missing"    // neither
)

type syncInfo struct {
	State SyncState
	Plain []byte // L (nil if absent)
	L     string // sha of L
	S, B  *version
	// Older — store is an ancestor of the base (branch switch, revert,
	// a published version dropped while resolving a git conflict).
	Older bool
}

func (c *Cage) storeSidecar(ref SecretRef) (string, error) {
	p, err := c.PlaintextPath(ref)
	if err != nil {
		return "", err
	}
	return p + ".store", nil
}

// syncState classifies a secret; it never decrypts.
func (c *Cage) syncState(ref SecretRef) (syncInfo, error) {
	var in syncInfo
	pp, err := c.PlaintextPath(ref)
	if err != nil {
		return in, err
	}
	plain, hasPlain, err := ReadFileIfExists(pp)
	if err != nil {
		return in, err
	}
	if in.S, err = c.readStoreVersion(ref); err != nil {
		return in, err
	}
	if in.B, err = c.readBase(ref, false); err != nil {
		return in, err
	}
	if hasPlain {
		in.Plain, in.L = plain, SHA256Hex(plain)
	}
	sidecar, err := c.storeSidecar(ref)
	if err != nil {
		return in, err
	}
	_, sideErr := os.Stat(sidecar)

	switch {
	case !hasPlain && in.S == nil:
		in.State = SyncMissing
	case in.S == nil:
		in.State = SyncLocalOnly
	case !hasPlain:
		in.State = SyncNew
	case hasConflictMarkers(plain) || sideErr == nil:
		in.State = SyncConflict
	case in.L == in.S.SHA:
		in.State = SyncInSync
	case in.B == nil:
		in.State = SyncDiverged
	case in.S.SHA == in.B.SHA:
		in.State = SyncModified
	case in.L == in.B.SHA && in.S.has(in.B.SHA):
		in.State = SyncOutdated
	default:
		in.State = SyncDiverged
		in.Older = in.B.has(in.S.SHA)
	}
	return in, nil
}

// requireEditable — a secret may be changed locally (edit commands,
// encrypt) only when the local copy is not behind or diverged from the
// store.
func requireEditable(ref SecretRef, in syncInfo) error {
	switch in.State {
	case SyncOutdated, SyncDiverged:
		return fmt.Errorf("%s: store has changes you have not merged (%s) — run `cage decrypt` first", ref, in.State)
	case SyncConflict:
		return fmt.Errorf("%s: unresolved conflict — edit the file or run `cage resolve %s -local|-store`", ref, ref)
	}
	return nil
}
