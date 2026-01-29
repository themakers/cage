package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/direnv/direnv/v2/pkg/dotenv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"gopkg.in/yaml.v3"
)

const (
	cfgName    = ".cage.yaml"
	cageSuffix = ".cage"
)

type Config struct {
	Recipients map[string][]string `yaml:"recipients"`
	Envs       map[string]struct {
		Files      []string `yaml:"files"`
		Recipients []string `yaml:"recipients"`
	} `yaml:"envs"`
}

/*** Новый формат без дублирования ***/
type CipherV2 struct {
	Cipher struct {
		Payload    string   `yaml:"payload"`    // base64(age blob, один на всех)
		Recipients []string `yaml:"recipients"` // SSH публичные ключи (для информации)
	} `yaml:"cipher"`
}

/*** Для опц. обратной совместимости (если вдруг встретится старый формат) ***/
type CipherEntryOld struct {
	Key    string `yaml:"key"`
	Secret string `yaml:"secret"`
}
type CipherOld struct {
	Cipher []CipherEntryOld `yaml:"cipher"`
}

/*** SSH identity discovery ***/

type SSHIdentity struct {
	Identity    age.Identity
	Source      string // human-readable
	Fingerprint string // optional
}

var (
	logger *slog.Logger
)

func main() {
	wdFlag := flag.String("wd", ".", "working directory (default: current directory)")
	flag.Parse()

	logger = newLoggerFromEnv()

	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	cmd := flag.Arg(0)

	wd, err := filepath.Abs(*wdFlag)
	must(err)

	logger.Debug("start", "cmd", cmd, "wd", wd)

	switch cmd {
	case "encrypt":
		runEncrypt(wd)
	case "decrypt":
		runDecrypt(wd)
	case "dump":
		if flag.NArg() != 2 {
			fatal("usage: cage [-wd DIR] dump <env-name>")
		}
		env := flag.Arg(1)
		runDump(wd, env)
	case "run":
		runRun(wd, flag.Args()[1:])
	default:
		usage()
		os.Exit(2)
	}
}

func newLoggerFromEnv() *slog.Logger {
	level := slog.LevelInfo
	if s := strings.TrimSpace(os.Getenv("CAGE_LOG_LEVEL")); s != "" {
		switch strings.ToLower(s) {
		case "debug":
			level = slog.LevelDebug
		case "info":
			level = slog.LevelInfo
		case "warn", "warning":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			// неизвестный уровень — оставим INFO, но отметим
			// (логгер ещё не создан, поэтому печатаем через stderr)
			fmt.Fprintf(os.Stderr, "cage: warn: unknown CAGE_LOG_LEVEL=%q, using INFO\n", s)
		}
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	return slog.New(h)
}

func usage() {
	fmt.Fprintf(os.Stderr, "cage - minimal secrets manager (age+SSH, single-blob format)\n")
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  cage [-wd DIR] encrypt\n")
	fmt.Fprintf(os.Stderr, "  cage [-wd DIR] decrypt\n")
	fmt.Fprintf(os.Stderr, "  cage [-wd DIR] dump <env-name>\n")
	fmt.Fprintf(os.Stderr, "  cage [-wd DIR] run (env:<name>|secret:<file>)... - <command> <args>...\n")
}

func runEncrypt(wd string) {
	cfg := loadConfig(filepath.Join(wd, cfgName))

	// Соберём множество файлов из всех env'ов
	filesSet := map[string]struct{}{}
	for envName, e := range cfg.Envs {
		for _, f := range e.Files {
			filesSet[f] = struct{}{}
			logger.Debug("env file", "env", envName, "file", f)
		}
	}
	if len(filesSet) == 0 {
		fatal("no files specified in any envs in %s", cfgName)
	}

	for file := range filesSet {
		sshKeys := collectRecipientsForFile(cfg, file)
		if len(sshKeys) == 0 {
			logger.Warn("no recipients for file, skipping", "file", file)
			continue
		}

		plainPath := filepath.Join(wd, file)
		data, err := os.ReadFile(plainPath)
		if err != nil {
			logger.Error("read plaintext failed, skipping", "file", file, "path", plainPath, "err", err)
			continue
		}

		logger.Info("encrypting file", "file", file, "bytes", len(data), "recipients", len(sshKeys))

		// Парсим получателей и шифруем один раз на всех
		var recips []age.Recipient
		for _, sshPub := range sshKeys {
			r, err := agessh.ParseRecipient(sshPub)
			if err != nil {
				logger.Warn("parse recipient failed (skipping)", "file", file, "recipient", sshPub, "err", err)
				continue
			}
			recips = append(recips, r)
		}
		if len(recips) == 0 {
			logger.Warn("no valid recipients after parsing, skipping", "file", file)
			continue
		}

		blob, err := ageEncryptBytes(data, recips...)
		if err != nil {
			logger.Error("encrypt failed", "file", file, "err", err)
			continue
		}

		// Готовим структуру V2
		var cf CipherV2
		cf.Cipher.Payload = base64.StdEncoding.EncodeToString(blob)
		keys := slices.Clone(sshKeys)
		sort.Strings(keys)
		cf.Cipher.Recipients = keys

		encPath := plainPath + cageSuffix
		if err := writeYAML(encPath, cf); err != nil {
			logger.Error("write cipher failed", "file", file, "path", encPath, "err", err)
			continue
		}

		logger.Info("encrypted", "file", file, "out", filepath.Base(encPath), "recipients", len(keys), "format", "v2-single-blob")
		fmt.Printf("encrypted: %s -> %s (%d recipients, single blob)\n", file, filepath.Base(encPath), len(keys))
	}
}

func runDecrypt(wd string) {
	idents := mustLoadSSHIdentities()
	logIdentityOrder(slog.LevelInfo, idents)

	matches, err := filepath.Glob(filepath.Join(wd, "*"+cageSuffix))
	must(err)
	if len(matches) == 0 {
		fatal("no *.cage files in %s", wd)
	}

	logger.Info("decrypt: found cipher files", "count", len(matches))

	for _, encPath := range matches {
		plain, ok, used, err := tryDecryptAnyFormatWithAnyIdentity(encPath, idents)
		if err != nil {
			logger.Error("decrypt error", "file", filepath.Base(encPath), "err", err)
			continue
		}
		if !ok {
			logger.Warn("cannot decrypt with any available SSH identity", "file", filepath.Base(encPath))
			continue
		}

		outPath := strings.TrimSuffix(encPath, cageSuffix)
		if err := os.WriteFile(outPath, plain, 0600); err != nil {
			logger.Error("write plaintext failed", "file", filepath.Base(outPath), "err", err)
			continue
		}

		logger.Info("decrypted", "in", filepath.Base(encPath), "out", filepath.Base(outPath), "identity", used)
		fmt.Printf("decrypted: %s -> %s\n", filepath.Base(encPath), filepath.Base(outPath))
	}
}

func runDump(wd, env string) {
	cfg := loadConfig(filepath.Join(wd, cfgName))
	envCfg, ok := cfg.Envs[env]
	if !ok {
		fatal("env %q not found in %s", env, cfgName)
	}

	idents, hasIdents := loadSSHIdentitiesOptional()
	if hasIdents {
		logIdentityOrder(slog.LevelInfo, idents)
	}

	logger.Info("dump", "env", env, "files", len(envCfg.Files), "has_identities", hasIdents)

	for _, file := range envCfg.Files {
		encPath := filepath.Join(wd, file+cageSuffix)
		plainPath := filepath.Join(wd, file)

		// Предпочесть зашифрованное, если расшифровывается любым ключом
		if fileExists(encPath) && hasIdents {
			if plain, ok, used, err := tryDecryptAnyFormatWithAnyIdentity(encPath, idents); err != nil {
				logger.Error("decrypt failed in dump", "file", file, "err", err)
			} else if ok {
				logger.Debug("dump: using decrypted", "file", file, "identity", used)
				_, _ = os.Stdout.Write(plain)
				continue
			}
		}

		// Иначе — plaintext, если есть
		if fileExists(plainPath) {
			logger.Debug("dump: using plaintext", "file", file)
			f, err := os.Open(plainPath)
			must(err)
			_, err = io.Copy(os.Stdout, f)
			_ = f.Close()
			must(err)
			continue
		}

		logger.Warn("dump: neither decryptable cipher nor plaintext found", "file", file, "cipher", filepath.Base(encPath), "plain", filepath.Base(plainPath))
		fmt.Fprintf(os.Stderr, "warn: neither decryptable %s.cage nor plaintext %s found\n", file, file)
	}
}

// cage run env:<name1> secret:<file2> ... - <command> <args>...
func runRun(wd string, args []string) {
	if len(args) == 0 {
		fatal("usage: cage [-wd DIR] run (env:<name>|secret:<file>)... - <command> <args>...")
	}
	dash := -1
	for i, a := range args {
		if a == "-" {
			dash = i
			break
		}
	}
	if dash <= 0 || dash == len(args)-1 {
		fatal("usage: cage [-wd DIR] run (env:<name>|secret:<file>)... - <command> <args>...")
	}
	specs := args[:dash]
	cmdArgs := args[dash+1:]

	cfg := loadConfig(filepath.Join(wd, cfgName))

	// index всех "секретов" (файлов), встречающихся в envs.*.files
	allFiles := map[string]struct{}{}
	for _, e := range cfg.Envs {
		for _, f := range e.Files {
			allFiles[f] = struct{}{}
		}
	}

	// разворачиваем specs в упорядоченный список файлов, без дублей (первое вхождение сохраняет порядок)
	var files []string
	seen := map[string]struct{}{}
	for _, s := range specs {
		switch {
		case strings.HasPrefix(s, "env:"):
			name := strings.TrimPrefix(s, "env:")
			envCfg, ok := cfg.Envs[name]
			if !ok {
				fatal("env %q not found in %s", name, cfgName)
			}
			for _, f := range envCfg.Files {
				if _, ok := seen[f]; ok {
					continue
				}
				seen[f] = struct{}{}
				files = append(files, f)
			}

		case strings.HasPrefix(s, "secret:"):
			f := strings.TrimPrefix(s, "secret:")
			if _, ok := allFiles[f]; !ok {
				fatal("secret %q not found in any envs.*.files in %s", f, cfgName)
			}
			if _, ok := seen[f]; ok {
				continue
			}
			seen[f] = struct{}{}
			files = append(files, f)

		default:
			fatal("bad spec %q (expected env:<name> or secret:<file>)", s)
		}
	}
	if len(files) == 0 {
		fatal("no secrets selected")
	}

	idents, hasIdents := loadSSHIdentitiesOptional()
	if hasIdents {
		logIdentityOrder(slog.LevelInfo, idents)
	}

	logger.Info("run: selected secrets", "count", len(files), "has_identities", hasIdents)

	// собираем переменные окружения из файлов
	vars := map[string]string{}
	for _, f := range files {
		b, err := readSecretBytesPreferEncrypted(wd, f, idents, hasIdents)
		if err != nil {
			fatal("%v", err)
		}
		for k, v := range dotenv.MustParse(string(b)) {
			vars[k] = v // последняя запись побеждает
		}
	}

	finalEnv := mergeEnv(os.Environ(), vars)

	// Расширяем argv до запуска, используя именно то окружение, с которым запускаем процесс
	cmdArgs = expandArgsVarRefOnly(cmdArgs, finalEnv)

	logger.Info("run: exec", "cmd", cmdArgs[0], "argc", len(cmdArgs)-1)

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = finalEnv

	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fatal("run: %v", err)
	}
}

var wholeVarRefRe = regexp.MustCompile(`^\$(\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)$`)

// expandArgsVarRefOnly расширяет аргумент ТОЛЬКО если он целиком является ссылкой на переменную:
//
//	$NAME  или  ${NAME}
//
// Также поддерживает случай, когда в argv доехали буквальные одинарные кавычки: '$NAME' или '${NAME}'.
func expandArgsVarRefOnly(args []string, env []string) []string {
	envMap := envSliceToMap(env)

	out := make([]string, 0, len(args))
	for _, a := range args {
		inner := a

		// Опционально: поддержка буквальных одинарных кавычек как символов в argv
		if len(inner) >= 2 && inner[0] == '\'' && inner[len(inner)-1] == '\'' {
			inner = inner[1 : len(inner)-1]
		}

		if !wholeVarRefRe.MatchString(inner) {
			out = append(out, a)
			continue
		}

		name := ""
		if len(inner) >= 4 && inner[1] == '{' && inner[len(inner)-1] == '}' {
			name = inner[2 : len(inner)-1]
		} else {
			name = inner[1:]
		}

		v, ok := envMap[name]
		if !ok {
			fatal("run: variable %s referenced in arg %q but not set", name, a)
		}
		out = append(out, v)
	}
	return out
}

func envSliceToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

func readSecretBytesPreferEncrypted(wd, file string, idents []SSHIdentity, hasIdents bool) ([]byte, error) {
	encPath := filepath.Join(wd, file+cageSuffix)
	plainPath := filepath.Join(wd, file)

	// как в dump: предпочесть зашифрованное, если оно расшифровывается любым identity
	if fileExists(encPath) && hasIdents {
		if plain, ok, used, err := tryDecryptAnyFormatWithAnyIdentity(encPath, idents); err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", filepath.Base(encPath), err)
		} else if ok {
			logger.Debug("readSecret: using decrypted", "file", file, "identity", used)
			return plain, nil
		}
	}

	if fileExists(plainPath) {
		b, err := os.ReadFile(plainPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		logger.Debug("readSecret: using plaintext", "file", file)
		return b, nil
	}

	// если plaintext нет, но .cage есть — значит без identity не можем
	if fileExists(encPath) && !hasIdents {
		return nil, fmt.Errorf("cannot decrypt %s (no usable SSH identities) and plaintext %s not found", filepath.Base(encPath), file)
	}
	return nil, fmt.Errorf("neither decryptable %s.cage nor plaintext %s found", file, file)
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// минимальный dotenv-парсер: KEY=VALUE, поддерживает "export ", комментарии (#) в начале строки,
// и простые кавычки '...' или "..." (в двойных — базовые escape).
func parseDotenv(b []byte) map[string]string {
	out := map[string]string{}
	lines := strings.Split(string(b), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, "export ") {
			ln = strings.TrimSpace(strings.TrimPrefix(ln, "export "))
		}
		i := strings.IndexByte(ln, '=')
		if i <= 0 {
			continue
		}
		k := strings.TrimSpace(ln[:i])
		if !envKeyRe.MatchString(k) {
			continue
		}
		v := strings.TrimSpace(ln[i+1:])

		// strip inline comment for unquoted values: KEY=val # comment
		if len(v) > 0 && v[0] != '"' && v[0] != '\'' {
			if j := strings.IndexByte(v, '#'); j >= 0 {
				v = strings.TrimSpace(v[:j])
			}
		}

		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			q := v[0]
			v = v[1 : len(v)-1]
			if q == '"' {
				v = unescapeDoubleQuoted(v)
			}
		}
		out[k] = v
	}
	return out
}

func unescapeDoubleQuoted(s string) string {
	// минимально полезные: \\ \" \n \r \t
	var buf strings.Builder
	buf.Grow(len(s))
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !esc {
			if c == '\\' {
				esc = true
				continue
			}
			buf.WriteByte(c)
			continue
		}
		esc = false
		switch c {
		case 'n':
			buf.WriteByte('\n')
		case 'r':
			buf.WriteByte('\r')
		case 't':
			buf.WriteByte('\t')
		case '\\':
			buf.WriteByte('\\')
		case '"':
			buf.WriteByte('"')
		default:
			// неизвестный escape — оставим как есть
			buf.WriteByte(c)
		}
	}
	if esc {
		buf.WriteByte('\\')
	}
	return buf.String()
}

func mergeEnv(base []string, vars map[string]string) []string {
	// vars должны переопределять base; при этом сохраняем прочие переменные
	seen := map[string]struct{}{}
	out := make([]string, 0, len(base)+len(vars))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 {
			k := kv[:i]
			if v, ok := vars[k]; ok {
				out = append(out, k+"="+v)
				seen[k] = struct{}{}
				continue
			}
			out = append(out, kv)
			seen[k] = struct{}{}
		} else {
			out = append(out, kv)
		}
	}
	// добавляем новые
	for k, v := range vars {
		if _, ok := seen[k]; ok {
			continue
		}
		out = append(out, k+"="+v)
	}
	return out
}

/*** Вспомогательные функции ***/

func collectRecipientsForFile(cfg Config, file string) []string {
	groupSet := map[string]struct{}{}
	for envName, e := range cfg.Envs {
		for _, f := range e.Files {
			if f == file {
				for _, g := range e.Recipients {
					groupSet[g] = struct{}{}
					logger.Debug("recipient group used", "file", file, "env", envName, "group", g)
				}
				break
			}
		}
	}
	sshSet := map[string]struct{}{}
	for g := range groupSet {
		keys, ok := cfg.Recipients[g]
		if !ok {
			logger.Warn("recipient group referenced but not defined", "group", g)
			continue
		}
		for _, k := range keys {
			sshSet[k] = struct{}{}
		}
	}
	var res []string
	for k := range sshSet {
		res = append(res, k)
	}
	return res
}

func tryDecryptAnyFormatWithAnyIdentity(encPath string, idents []SSHIdentity) ([]byte, bool, string, error) {
	b, err := os.ReadFile(encPath)
	if err != nil {
		return nil, false, "", err
	}

	// Пытаемся как V2
	var v2 CipherV2
	if err := yaml.Unmarshal(b, &v2); err == nil && v2.Cipher.Payload != "" {
		ciph, err := base64.StdEncoding.DecodeString(v2.Cipher.Payload)
		if err != nil {
			return nil, false, "", err
		}
		for _, id := range idents {
			plain, err := ageDecryptBytes(ciph, id.Identity)
			if err == nil {
				return plain, true, id.describe(), nil
			}
			logger.Debug("v2 decrypt failed with identity", "file", filepath.Base(encPath), "identity", id.describe(), "err", err)
		}
		// формат валиден, но не подошёл ни один identity
		return nil, false, "", nil
	}

	// На всякий случай — как старый формат (один из блоков подойдёт)
	var old CipherOld
	if err := yaml.Unmarshal(b, &old); err == nil && len(old.Cipher) > 0 {
		for _, entry := range old.Cipher {
			ciph, err := base64.StdEncoding.DecodeString(entry.Secret)
			if err != nil {
				continue
			}
			for _, id := range idents {
				plain, err := ageDecryptBytes(ciph, id.Identity)
				if err == nil {
					return plain, true, id.describe(), nil
				}
				logger.Debug("old decrypt failed with identity", "file", filepath.Base(encPath), "identity", id.describe(), "err", err)
			}
		}
		return nil, false, "", nil
	}

	return nil, false, "", fmt.Errorf("unrecognized cipher file format")
}

func (id SSHIdentity) describe() string {
	if id.Fingerprint != "" {
		return id.Source + " (" + id.Fingerprint + ")"
	}
	return id.Source
}

func ageEncryptBytes(plain []byte, recipients ...age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ageDecryptBytes(ciph []byte, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(ciph), identity)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func loadConfig(path string) Config {
	var cfg Config
	if err := readYAML(path, &cfg); err != nil {
		fatal("read %s: %v", filepath.Base(path), err)
	}
	return cfg
}

func writeYAML(path string, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func readYAML(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

func must(err error) {
	if err != nil {
		fatal("%v", err)
	}
}

func fatal(fmtStr string, a ...any) {
	fmt.Fprintf(os.Stderr, "cage: "+fmtStr+"\n", a...)
	os.Exit(1)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

/*** Multi-identity discovery & loading ***/

func mustLoadSSHIdentities() []SSHIdentity {
	ids, ok := loadSSHIdentitiesOptional()
	if !ok {
		fatal("no usable SSH identities found (checked CAGE_SSH_IDENTITY, ssh-agent, ~/.ssh/config, ~/.ssh/id_*, ~/.ssh scan)")
	}
	return ids
}

func loadSSHIdentitiesOptional() ([]SSHIdentity, bool) {
	ids, err := discoverSSHIdentities()
	if err != nil {
		logger.Warn("identity discovery error (continuing with what we have)", "err", err)
	}
	if len(ids) == 0 {
		return nil, false
	}
	logger.Info("loaded SSH identities", "count", len(ids))
	for _, id := range ids {
		logger.Debug("identity", "source", id.Source, "fingerprint", id.Fingerprint)
	}
	return ids, true
}

func discoverSSHIdentities() ([]SSHIdentity, error) {
	var out []SSHIdentity
	seen := map[string]struct{}{} // fingerprint or source fallback

	add := func(id SSHIdentity) {
		key := id.Fingerprint
		if key == "" {
			key = id.Source
		}
		if _, ok := seen[key]; ok {
			logger.Debug("skip duplicate identity", "identity", id.describe())
			return
		}
		seen[key] = struct{}{}
		out = append(out, id)
	}

	// 0) CAGE_SSH_IDENTITY: либо текст ключа, либо путь к файлу
	if id, ok := identityFromCAGEEnv(); ok {
		logger.Debug("found identity from CAGE_SSH_IDENTITY", "identity", id.describe())
		add(id)
	} else {
		logger.Debug("no usable identity from CAGE_SSH_IDENTITY")
	}

	// 1) ssh-agent
	//agentIds, aerr := identitiesFromSSHAgent()
	//if aerr != nil {
	//	logger.Debug("ssh-agent identities error", "err", aerr)
	//}
	//for _, id := range agentIds {
	//	add(id)
	//}

	// 2) ~/.ssh/config: все IdentityFile
	cfgIds, cerr := identitiesFromSSHConfig()
	if cerr != nil {
		logger.Debug("ssh config identities error", "err", cerr)
	}
	for _, id := range cfgIds {
		add(id)
	}

	// 3) стандартные id_*
	stdIds, serr := identitiesFromStandardSSHFiles()
	if serr != nil {
		logger.Debug("standard ssh identities error", "err", serr)
	}
	for _, id := range stdIds {
		add(id)
	}

	// 4) скан ~/.ssh
	scanIds, scerr := identitiesFromSSHDirScan()
	if scerr != nil {
		logger.Debug("ssh dir scan identities error", "err", scerr)
	}
	for _, id := range scanIds {
		add(id)
	}

	return out, nil
}

func identityFromCAGEEnv() (SSHIdentity, bool) {
	val := strings.TrimSpace(os.Getenv("CAGE_SSH_IDENTITY"))
	if val == "" {
		return SSHIdentity{}, false
	}

	// Если выглядит как PEM (включая OpenSSH), пробуем парсить напрямую.
	if looksLikePrivateKeyPEM(val) {
		ident, err := agessh.ParseIdentity([]byte(val))
		if err != nil {
			logger.Warn("CAGE_SSH_IDENTITY looks like key text but parse failed", "err", err)
			return SSHIdentity{}, false
		}
		return SSHIdentity{
			Identity:    ident,
			Source:      "CAGE_SSH_IDENTITY(text)",
			Fingerprint: "", // без .pub сложно/необязательно
		}, true
	}

	// Иначе считаем, что это путь
	home, _ := os.UserHomeDir()
	p := expandTilde(val, home)
	if !filepath.IsAbs(p) && home != "" {
		// допускаем относительный путь от CWD
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
	}
	if !fileExists(p) {
		logger.Debug("CAGE_SSH_IDENTITY is set but not a key text and file doesn't exist", "value", val, "path", p)
		return SSHIdentity{}, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		logger.Warn("read CAGE_SSH_IDENTITY(path) failed", "path", p, "err", err)
		return SSHIdentity{}, false
	}
	ident, err := agessh.ParseIdentity(b)
	if err != nil {
		logger.Warn("parse CAGE_SSH_IDENTITY(path) failed", "path", p, "err", err)
		return SSHIdentity{}, false
	}
	fp := fingerprintFromPubFileIfExists(p + ".pub")
	return SSHIdentity{
		Identity:    ident,
		Source:      "CAGE_SSH_IDENTITY(path:" + filepath.Base(p) + ")",
		Fingerprint: fp,
	}, true
}

func looksLikePrivateKeyPEM(s string) bool {
	// достаточно грубо: наличие BEGIN и PRIVATE KEY
	if !strings.Contains(s, "BEGIN") {
		return false
	}
	if !strings.Contains(s, "PRIVATE KEY") {
		return false
	}
	return true
}

func identitiesFromSSHAgent() ([]SSHIdentity, error) {
	sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if sock == "" {
		logger.Debug("SSH_AUTH_SOCK not set, skipping ssh-agent")
		return nil, nil
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	// не закрываем сразу: Signers() использует conn синхронно, но закрытие после получения signers ок.
	defer conn.Close()

	c := agent.NewClient(conn)
	signers, err := c.Signers()
	if err != nil {
		return nil, err
	}

	var out []SSHIdentity
	for _, s := range signers {
		pub := s.PublicKey()
		fp := ssh.FingerprintSHA256(pub)
		logger.Debug("agent signer public key", "fp", fp, "type", pub.Type())

		// здесь мы добавляем запись **для поиска приватника с таким же публичным ключом**
		out = append(out, SSHIdentity{
			Identity:    nil, // не identity, только public key indicator
			Source:      "ssh-agent(pub:" + fp + ")",
			Fingerprint: fp,
		})
	}

	if len(out) > 0 {
		logger.Info("ssh-agent identities loaded", "count", len(out))
	} else {
		logger.Debug("ssh-agent present but no usable identities produced")
	}

	return out, nil
}

func identitiesFromSSHConfig() ([]SSHIdentity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")
	cfgPath := filepath.Join(sshDir, "config")

	b, err := os.ReadFile(cfgPath)
	if err != nil {
		// нет конфига — это ок
		return nil, nil
	}

	paths := identityFilesFromConfig(string(b))
	if len(paths) == 0 {
		return nil, nil
	}

	var out []SSHIdentity
	for _, p := range paths {
		pp := expandTilde(strings.TrimSpace(p), home)
		if !filepath.IsAbs(pp) {
			// ssh трактует относительные пути как относительно ~/.ssh
			pp = filepath.Join(sshDir, pp)
		}
		id, ok := identityFromPrivateKeyFile(pp, "ssh-config:"+filepath.Base(pp))
		if ok {
			out = append(out, id)
		}
	}

	if len(out) > 0 {
		logger.Info("ssh-config identities loaded", "count", len(out))
	}

	return out, nil
}

func identityFilesFromConfig(cfg string) []string {
	re := regexp.MustCompile(`(?i)^\s*IdentityFile\s+(.+?)\s*$`)
	lines := strings.Split(cfg, "\n")
	var out []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		m := re.FindStringSubmatch(ln)
		if len(m) == 2 {
			p := strings.Trim(m[1], `"`)
			out = append(out, p)
		}
	}
	return out
}

func identitiesFromStandardSSHFiles() ([]SSHIdentity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")

	candidates := []string{
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_rsa"),
		filepath.Join(sshDir, "id_ecdsa"),
		filepath.Join(sshDir, "id_ed25519_sk"),
		filepath.Join(sshDir, "id_rsa_sk"),
		filepath.Join(sshDir, "id_ecdsa_sk"),
	}

	var out []SSHIdentity
	for _, p := range candidates {
		id, ok := identityFromPrivateKeyFile(p, "standard:"+filepath.Base(p))
		if ok {
			out = append(out, id)
		}
	}

	if len(out) > 0 {
		logger.Info("standard ~/.ssh/id_* identities loaded", "count", len(out))
	}

	return out, nil
}

func identitiesFromSSHDirScan() ([]SSHIdentity, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		// нет ~/.ssh — ничего страшного
		return nil, nil
	}

	skipNames := map[string]struct{}{
		"config":          {},
		"known_hosts":     {},
		"known_hosts.old": {},
		"authorized_keys": {},
	}

	var out []SSHIdentity
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if _, ok := skipNames[name]; ok {
			continue
		}
		if strings.HasSuffix(name, ".pub") {
			continue
		}

		p := filepath.Join(sshDir, name)
		id, ok := identityFromPrivateKeyFile(p, "scan:"+name)
		if ok {
			out = append(out, id)
		}
	}

	if len(out) > 0 {
		logger.Info("ssh dir scan identities loaded", "count", len(out))
	}

	return out, nil
}

func identityFromPrivateKeyFile(path string, source string) (SSHIdentity, bool) {
	if !fileExists(path) {
		return SSHIdentity{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		logger.Debug("read private key failed", "path", path, "err", err)
		return SSHIdentity{}, false
	}

	ident, err := agessh.ParseIdentity(b)
	if err != nil {
		// passphrase-protected или неподдерживаемый формат — просто пропускаем
		logger.Debug("parse identity failed (skipping)", "path", path, "err", err)
		return SSHIdentity{}, false
	}

	fp := fingerprintFromPubFileIfExists(path + ".pub")

	return SSHIdentity{
		Identity:    ident,
		Source:      source,
		Fingerprint: fp,
	}, true
}

func fingerprintFromPubFileIfExists(pubPath string) string {
	b, err := os.ReadFile(pubPath)
	if err != nil {
		return ""
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(b))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pk)
}

func expandTilde(p, home string) string {
	if strings.HasPrefix(p, "~") {
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

func logIdentityOrder(level slog.Level, ids []SSHIdentity) {
	if len(ids) == 0 {
		logger.Log(nil, level, "identity order: <none>")
		return
	}
	parts := make([]string, 0, len(ids))
	for i, id := range ids {
		parts = append(parts, fmt.Sprintf("%02d: %s", i+1, id.describe()))
	}
	logger.Log(nil, level, "identity order", "count", len(ids), "order", strings.Join(parts, " | "))
}

/*** Utility if needed later ***/
func listFilesRecursive(dir string, match func(path string, d fs.DirEntry) bool) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if match(path, d) {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}
