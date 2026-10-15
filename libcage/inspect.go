package libcage

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Inspection describes secrets without revealing values: names, places,
// shapes and keyed fingerprints. Fingerprints use a random key of one call:
// equal values get equal fingerprints within a report, and a fingerprint
// cannot be checked against a guessed value afterwards.

type InspectURI struct {
	Scheme       string   `json:"scheme"`
	User         string   `json:"user,omitempty"`
	Hosts        []string `json:"hosts"`
	Path         string   `json:"path,omitempty"`
	QueryKeys    []string `json:"query_keys,omitempty"`
	PasswordFP   string   `json:"password_fp,omitempty"`
	PasswordLen  int      `json:"password_len,omitempty"`
	PasswordDups []string `json:"password_dups,omitempty"`
}

type InspectVar struct {
	Key         string      `json:"key"`
	Line        int         `json:"line"`
	Commented   bool        `json:"commented,omitempty"`
	Comment     string      `json:"comment,omitempty"`
	Shape       string      `json:"shape"`
	Length      int         `json:"length"`
	Charset     string      `json:"charset,omitempty"`
	Fingerprint string      `json:"fp,omitempty"`
	URI         *InspectURI `json:"uri,omitempty"`
	ParseError  string      `json:"parse_error,omitempty"`
	// Dups — other places with the same value ("ref:KEY", "ref:KEY#password").
	Dups []string `json:"dups,omitempty"`
}

type InspectFile struct {
	Ref         string       `json:"ref"`
	Source      string       `json:"source"` // plaintext | store | none
	Error       string       `json:"error,omitempty"`
	Envs        []string     `json:"envs,omitempty"`
	Vars        []InspectVar `json:"vars,omitempty"`
	BlobKind    string       `json:"blob_kind,omitempty"`
	BlobSize    int          `json:"blob_size,omitempty"`
	BlobFP      string       `json:"blob_fp,omitempty"`
	BlobDups    []string     `json:"blob_dups,omitempty"`
	Unreadable  bool         `json:"unreadable,omitempty"`
	NotInConfig bool         `json:"not_in_config,omitempty"`
}

type InspectReport struct {
	Files []InspectFile `json:"files"`
}

// Inspect describes the secrets of specs (refs, @env); no specs — every
// secret of cage.yaml and every plaintext file in the configured dirs.
func (c *Cage) Inspect(specs []string) (InspectReport, error) {
	if c.Root == "" || c.Cfg == nil {
		return InspectReport{}, fmt.Errorf("inspect requires cage root")
	}
	refs, notInConfig, err := c.inspectRefs(specs)
	if err != nil {
		return InspectReport{}, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return InspectReport{}, err
	}
	fp := func(v string) string {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(v))
		return hex.EncodeToString(m.Sum(nil))[:12]
	}

	type place struct {
		file, varIdx int
		password     bool
		blob         bool
	}
	byFP := map[string][]place{}
	label := func(rep *InspectReport, p place) string {
		f := rep.Files[p.file]
		if p.blob {
			return f.Ref
		}
		s := f.Ref + ":" + f.Vars[p.varIdx].Key
		if p.password {
			s += "#password"
		}
		return s
	}

	var rep InspectReport
	for _, ref := range refs {
		f := InspectFile{Ref: ref.String(), Envs: c.ReferencedBy(ref), NotInConfig: notInConfig[ref]}
		sort.Strings(f.Envs)
		plain, source, err := c.readForInspect(ref)
		f.Source = source
		switch {
		case isNotRecipient(err):
			f.Unreadable = true
			f.Error = "not a recipient"
		case err != nil:
			f.Error = err.Error()
		}
		fi := len(rep.Files)
		if err == nil && source != "none" {
			if IsEnvSecretName(ref.Name) {
				f.Vars = inspectEnv(plain, fp)
				for vi, v := range f.Vars {
					if v.Fingerprint != "" {
						byFP[v.Fingerprint] = append(byFP[v.Fingerprint], place{file: fi, varIdx: vi})
					}
					if v.URI != nil && v.URI.PasswordFP != "" {
						byFP[v.URI.PasswordFP] = append(byFP[v.URI.PasswordFP], place{file: fi, varIdx: vi, password: true})
					}
				}
			} else {
				f.BlobKind, f.BlobSize, f.BlobFP = blobKind(plain), len(plain), fp(string(plain))
				byFP[f.BlobFP] = append(byFP[f.BlobFP], place{file: fi, blob: true})
			}
		}
		rep.Files = append(rep.Files, f)
	}

	for _, places := range byFP {
		if len(places) < 2 {
			continue
		}
		for _, p := range places {
			var others []string
			for _, o := range places {
				if o != p {
					others = append(others, label(&rep, o))
				}
			}
			sort.Strings(others)
			f := &rep.Files[p.file]
			switch {
			case p.blob:
				f.BlobDups = others
			case p.password:
				f.Vars[p.varIdx].URI.PasswordDups = others
			default:
				f.Vars[p.varIdx].Dups = others
			}
		}
	}
	return rep, nil
}

func (c *Cage) inspectRefs(specs []string) ([]SecretRef, map[SecretRef]bool, error) {
	seen := map[SecretRef]bool{}
	notInConfig := map[SecretRef]bool{}
	var refs []SecretRef
	add := func(r SecretRef) {
		if !seen[r] {
			seen[r] = true
			refs = append(refs, r)
		}
	}
	if len(specs) > 0 {
		for _, s := range specs {
			if strings.HasPrefix(s, "@") {
				env, ok := c.Cfg.Envs[strings.TrimPrefix(s, "@")]
				if !ok {
					return nil, nil, fmt.Errorf("unknown env %q", s)
				}
				for _, fs := range env.Files {
					r, err := ParseSecretRef(fs)
					if err != nil {
						return nil, nil, err
					}
					add(r)
				}
				continue
			}
			r, err := ParseSecretRef(s)
			if err != nil {
				return nil, nil, err
			}
			add(r)
		}
		return refs, notInConfig, nil
	}
	for _, r := range c.AllRefs() {
		add(r)
	}
	for _, r := range c.PlaintextRefs() {
		if !seen[r] {
			notInConfig[r] = true
			add(r)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].String() < refs[j].String() })
	return refs, notInConfig, nil
}

// AllRefs — every secret referenced by envs of cage.yaml.
func (c *Cage) AllRefs() []SecretRef {
	seen := map[SecretRef]bool{}
	var out []SecretRef
	for _, env := range c.Cfg.Envs {
		for _, fs := range env.Files {
			if r, err := ParseSecretRef(fs); err == nil && !seen[r] {
				seen[r] = true
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// PlaintextRefs — plaintext files present in the configured dirs (one
// level, .gitignore excluded).
func (c *Cage) PlaintextRefs() []SecretRef {
	var out []SecretRef
	for alias, rel := range c.Cfg.Dirs {
		ents, err := os.ReadDir(filepath.Join(c.Root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || e.Name() == ".gitignore" || strings.HasPrefix(e.Name(), ".") || strings.HasSuffix(e.Name(), ".store") {
				continue
			}
			out = append(out, SecretRef{Dir: alias, Name: e.Name()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (c *Cage) readForInspect(ref SecretRef) ([]byte, string, error) {
	p, err := c.PlaintextPath(ref)
	if err != nil {
		return nil, "none", err
	}
	if b, ok, err := ReadFileIfExists(p); err != nil {
		return nil, "none", err
	} else if ok {
		return b, "plaintext", nil
	}
	storePath, err := c.StoreSecretPath(ref)
	if err != nil {
		return nil, "none", err
	}
	b, ok, err := ReadFileIfExists(storePath)
	if err != nil {
		return nil, "none", err
	}
	if !ok {
		return nil, "none", fmt.Errorf("neither plaintext nor store file")
	}
	s, err := ParseSecretV1(b)
	if err != nil {
		return nil, "store", err
	}
	plain, err := c.decryptSecret(s)
	return plain, "store", err
}

func inspectEnv(plain []byte, fp func(string) string) []InspectVar {
	f := ParseDotenvFile(plain)
	var out []InspectVar
	var comment []string
	for i, l := range f.Lines {
		switch {
		case l.IsComment():
			comment = append(comment, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l.Raw), "#")))
			continue
		case !l.IsAssign():
			comment = nil
			continue
		}
		v := InspectVar{Key: l.Key, Line: i + 1, Commented: l.Commented, Comment: strings.Join(comment, " / ")}
		comment = nil
		val, err := l.Value()
		if err != nil {
			v.ParseError = err.Error()
			out = append(out, v)
			continue
		}
		describeValue(&v, val, fp)
		out = append(out, v)
	}
	return out
}

func describeValue(v *InspectVar, val string, fp func(string) string) {
	v.Length = len(val)
	v.Charset = charset(val)
	if val == "" {
		v.Shape = "empty"
		return
	}
	v.Fingerprint = fp(val)
	switch {
	case strings.Contains(val, "-----BEGIN"):
		v.Shape = "pem"
	case LooksLikeSSHPublicKeyLine(val):
		v.Shape = "ssh-public-key"
	case isJWT(val):
		v.Shape = "jwt"
	default:
		if u, err := url.Parse(val); err == nil && u.Scheme != "" && u.Host != "" && !strings.ContainsAny(val, " \t") {
			v.Shape = "uri"
			iu := &InspectURI{Scheme: u.Scheme, User: u.User.Username(), Hosts: strings.Split(u.Host, ","), Path: u.Path}
			for k := range u.Query() {
				iu.QueryKeys = append(iu.QueryKeys, k)
			}
			sort.Strings(iu.QueryKeys)
			if p, ok := u.User.Password(); ok {
				iu.PasswordFP, iu.PasswordLen = fp(p), len(p)
			}
			v.URI = iu
			return
		}
		if _, err := strconv.ParseFloat(val, 64); err == nil {
			v.Shape = "number"
		} else if val == "true" || val == "false" {
			v.Shape = "bool"
		} else {
			v.Shape = "string"
		}
	}
}

func isJWT(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 && strings.HasPrefix(s, "eyJ")
}

func charset(s string) string {
	var lower, upper, digit, symbol, space bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsSpace(r):
			space = true
		default:
			symbol = true
		}
	}
	var out []string
	for _, c := range []struct {
		on   bool
		name string
	}{{lower, "lower"}, {upper, "upper"}, {digit, "digit"}, {symbol, "symbol"}, {space, "space"}} {
		if c.on {
			out = append(out, c.name)
		}
	}
	return strings.Join(out, ",")
}

func blobKind(b []byte) string {
	s := string(b)
	switch {
	case strings.Contains(s, "BEGIN OPENSSH PRIVATE KEY"):
		return "ssh-private-key"
	case strings.Contains(s, "-----BEGIN"):
		return "pem"
	case strings.HasPrefix(strings.TrimSpace(s), "{"):
		return "json"
	default:
		for _, r := range s {
			if r == 0 || (r < 32 && r != '\n' && r != '\r' && r != '\t') {
				return "binary"
			}
		}
		return "text"
	}
}

// StatusFile — one secret: plaintext vs store, readability, consumers.
type StatusFile struct {
	Ref string `json:"ref"`
	// State — SyncState: in-sync | modified | outdated | diverged | conflict |
	// new | local-only | missing; foreign — encrypted for other recipients.
	State           string   `json:"state"`
	Hint            string   `json:"hint,omitempty"`
	RecipientsStale bool     `json:"recipients_stale,omitempty"`
	Readable        bool     `json:"readable"`
	Envs            []string `json:"envs,omitempty"`
	Recipients      []string `json:"recipients,omitempty"`
}

func syncHint(ref SecretRef, in syncInfo) string {
	switch in.State {
	case SyncModified, SyncLocalOnly:
		return "local changes — `cage encrypt`, then commit"
	case SyncOutdated, SyncNew:
		return "store is newer — `cage decrypt`"
	case SyncDiverged:
		if in.Older {
			return "store is older than your copy (revert/branch switch?) — `cage decrypt` marks the differences"
		}
		return "changed locally and in store — `cage decrypt` merges"
	case SyncConflict:
		return "unresolved conflict — edit the file or `cage resolve " + ref.String() + " -local|-store`"
	}
	return ""
}

type StatusConflict struct {
	Env     string   `json:"env"`
	Var     string   `json:"var"`
	Sources []string `json:"sources"`
}

type StatusReport struct {
	Files []StatusFile `json:"files"`
	// NotInConfig — plaintext files that no env references.
	NotInConfig []string `json:"not_in_config,omitempty"`
	// StoreOrphans — store files that no env references.
	StoreOrphans []string         `json:"store_orphans,omitempty"`
	Conflicts    []StatusConflict `json:"conflicts,omitempty"`
	// StaleEnvs — compiled envs that differ from their store files (e.g.
	// after a git merge) — `cage encrypt` rebuilds them.
	StaleEnvs []string `json:"stale_envs,omitempty"`
}

// Status compares plaintext with the store and finds variable collisions
// within envs (only for secrets this identity can read).
func (c *Cage) Status() (StatusReport, error) {
	if c.Root == "" || c.Cfg == nil {
		return StatusReport{}, fmt.Errorf("status requires cage root")
	}
	recips, _, err := c.buildRecipientPlan()
	if err != nil {
		return StatusReport{}, err
	}
	keyNames := map[string][]string{}
	for name, vals := range c.Cfg.Recipients {
		for _, v := range vals {
			if LooksLikeSSHPublicKeyLine(v) {
				k := normalizeKeyLine(v)
				keyNames[k] = append(keyNames[k], name)
			}
		}
	}

	var rep StatusReport
	if _, envRefs, err := c.buildRecipientPlan(); err == nil {
		for envName, refs := range envRefs {
			p, _ := c.StoreEnvPath(envName)
			want, err := c.compileEnv(envName, refs)
			if err != nil {
				continue
			}
			if got, ok, _ := ReadFileIfExists(p); !ok || !BytesEqual(got, want) {
				rep.StaleEnvs = append(rep.StaleEnvs, envName)
			}
		}
		sort.Strings(rep.StaleEnvs)
	}
	inConfig := map[SecretRef]bool{}
	for _, ref := range c.AllRefs() {
		inConfig[ref] = true
		sf := StatusFile{Ref: ref.String(), Envs: c.ReferencedBy(ref)}
		sort.Strings(sf.Envs)
		names := map[string]bool{}
		for _, k := range recips[ref] {
			ns := keyNames[normalizeKeyLine(k)]
			if len(ns) == 0 {
				names[normalizeKeyLine(k)] = true
			}
			for _, n := range ns {
				names[n] = true
			}
		}
		for n := range names {
			sf.Recipients = append(sf.Recipients, n)
		}
		sort.Strings(sf.Recipients)

		in, err := c.syncState(ref)
		if err != nil {
			sf.State, sf.Hint = "error", err.Error()
			rep.Files = append(rep.Files, sf)
			continue
		}
		sf.State = string(in.State)
		sf.Readable = in.Plain != nil
		if in.S != nil && in.Plain == nil {
			_, err := c.decryptSecret(in.S.File)
			sf.Readable = err == nil
		}
		sf.Hint = syncHint(ref, in)
		if in.State == SyncNew && !sf.Readable {
			sf.State, sf.Hint = "foreign", ""
		}
		if in.S != nil && !equalStringSlices(in.S.File.Secret.Recipients, NormalizeRecipients(recips[ref])) {
			sf.RecipientsStale = true
			if sf.Hint == "" {
				sf.Hint = "recipients changed in cage.yaml — `cage encrypt` re-encrypts"
			}
		}
		rep.Files = append(rep.Files, sf)
	}
	for _, r := range c.PlaintextRefs() {
		if !inConfig[r] {
			rep.NotInConfig = append(rep.NotInConfig, r.String())
		}
	}
	for alias := range c.Cfg.Dirs {
		ents, _ := os.ReadDir(filepath.Join(c.StoreDir(), "files", alias))
		for _, e := range ents {
			r := SecretRef{Dir: alias, Name: strings.TrimSuffix(e.Name(), ".cage")}
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".cage") && !inConfig[r] {
				rep.StoreOrphans = append(rep.StoreOrphans, r.String())
			}
		}
	}
	sort.Strings(rep.StoreOrphans)

	envNames := make([]string, 0, len(c.Cfg.Envs))
	for n := range c.Cfg.Envs {
		envNames = append(envNames, n)
	}
	sort.Strings(envNames)
	for _, en := range envNames {
		sources := map[string][]string{}
		for _, fs := range c.Cfg.Envs[en].Files {
			ref, err := ParseSecretRef(fs)
			if err != nil || !IsEnvSecretName(ref.Name) {
				continue
			}
			plain, _, err := c.readForInspect(ref)
			if err != nil {
				continue
			}
			m, err := ParseDotenv(plain)
			if err != nil {
				continue
			}
			for k := range m {
				sources[k] = append(sources[k], ref.String())
			}
		}
		for k, srcs := range sources {
			if len(srcs) > 1 {
				sort.Strings(srcs)
				rep.Conflicts = append(rep.Conflicts, StatusConflict{Env: en, Var: k, Sources: srcs})
			}
		}
	}
	sort.Slice(rep.Conflicts, func(i, j int) bool {
		if rep.Conflicts[i].Env != rep.Conflicts[j].Env {
			return rep.Conflicts[i].Env < rep.Conflicts[j].Env
		}
		return rep.Conflicts[i].Var < rep.Conflicts[j].Var
	})
	return rep, nil
}
