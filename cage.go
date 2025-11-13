package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"gopkg.in/yaml.v3"
)

const (
	cfgName         = ".cage.yaml"
	cageSuffix      = ".cage"
	openSSHPEMStart = "-----BEGIN OPENSSH PRIVATE KEY-----"
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

func main() {
	wdFlag := flag.String("wd", ".", "working directory (default: current directory)")
	flag.Parse()

	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	cmd := flag.Arg(0)

	wd, err := filepath.Abs(*wdFlag)
	must(err)

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
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "cage - minimal secrets manager (age+SSH, single-blob format)\n")
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  cage [-wd DIR] encrypt\n")
	fmt.Fprintf(os.Stderr, "  cage [-wd DIR] decrypt\n")
	fmt.Fprintf(os.Stderr, "  cage [-wd DIR] dump <env-name>\n")
}

func runEncrypt(wd string) {
	cfg := loadConfig(filepath.Join(wd, cfgName))

	// Соберём множество файлов из всех env'ов
	filesSet := map[string]struct{}{}
	for _, e := range cfg.Envs {
		for _, f := range e.Files {
			filesSet[f] = struct{}{}
		}
	}
	if len(filesSet) == 0 {
		fatal("no files specified in any envs in %s", cfgName)
	}

	for file := range filesSet {
		sshKeys := collectRecipientsForFile(cfg, file)
		if len(sshKeys) == 0 {
			fmt.Fprintf(os.Stderr, "warn: file %q has no recipients (skipping)\n", file)
			continue
		}
		// plaintext
		plainPath := filepath.Join(wd, file)
		data, err := os.ReadFile(plainPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read %s: %v\n", file, err)
			continue
		}
		// Парсим получателей и шифруем один раз на всех
		var recips []age.Recipient
		for _, sshPub := range sshKeys {
			r, err := agessh.ParseRecipient(sshPub)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: parse recipient %q: %v\n", sshPub, err)
				continue
			}
			recips = append(recips, r)
		}
		if len(recips) == 0 {
			fmt.Fprintf(os.Stderr, "warn: no valid recipients for %q (skipping)\n", file)
			continue
		}
		blob, err := ageEncryptBytes(data, recips...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: encrypt %q: %v\n", file, err)
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
			fmt.Fprintf(os.Stderr, "error: write %s: %v\n", encPath, err)
			continue
		}
		fmt.Printf("encrypted: %s -> %s (%d recipients, single blob)\n", file, filepath.Base(encPath), len(keys))
	}
}

func runDecrypt(wd string) {
	identity := mustLoadSSHIdentity()

	matches, err := filepath.Glob(filepath.Join(wd, "*"+cageSuffix))
	must(err)
	if len(matches) == 0 {
		fatal("no *.cage files in %s", wd)
	}

	for _, encPath := range matches {
		plain, ok, err := tryDecryptAnyFormat(encPath, identity)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", filepath.Base(encPath), err)
			continue
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "warn: cannot decrypt %s with your SSH identity\n", filepath.Base(encPath))
			continue
		}
		outPath := strings.TrimSuffix(encPath, cageSuffix)
		if err := os.WriteFile(outPath, plain, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error: write %s: %v\n", filepath.Base(outPath), err)
			continue
		}
		fmt.Printf("decrypted: %s -> %s\n", filepath.Base(encPath), filepath.Base(outPath))
	}
}

func runDump(wd, env string) {
	cfg := loadConfig(filepath.Join(wd, cfgName))
	envCfg, ok := cfg.Envs[env]
	if !ok {
		fatal("env %q not found in %s", env, cfgName)
	}
	identity := mustLoadSSHIdentity()

	for _, file := range envCfg.Files {
		encPath := filepath.Join(wd, file+cageSuffix)
		plainPath := filepath.Join(wd, file)

		// Предпочесть зашифрованное, если расшифровывается нашим ключом
		if fileExists(encPath) {
			if plain, ok, _ := tryDecryptAnyFormat(encPath, identity); ok {
				os.Stdout.Write(plain)
				continue
			}
		}
		// Иначе — plaintext, если есть
		if fileExists(plainPath) {
			f, err := os.Open(plainPath)
			must(err)
			_, err = io.Copy(os.Stdout, f)
			f.Close()
			must(err)
			continue
		}
		fmt.Fprintf(os.Stderr, "warn: neither decryptable %s.cage nor plaintext %s found\n", file, file)
	}
}

/*** Вспомогательные функции ***/

func collectRecipientsForFile(cfg Config, file string) []string {
	groupSet := map[string]struct{}{}
	for _, e := range cfg.Envs {
		for _, f := range e.Files {
			if f == file {
				for _, g := range e.Recipients {
					groupSet[g] = struct{}{}
				}
				break
			}
		}
	}
	sshSet := map[string]struct{}{}
	for g := range groupSet {
		keys, ok := cfg.Recipients[g]
		if !ok {
			fmt.Fprintf(os.Stderr, "warn: recipient group %q referenced but not defined\n", g)
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

func tryDecryptAnyFormat(encPath string, identity age.Identity) ([]byte, bool, error) {
	b, err := os.ReadFile(encPath)
	if err != nil {
		return nil, false, err
	}
	// Пытаемся как V2
	var v2 CipherV2
	if err := yaml.Unmarshal(b, &v2); err == nil && v2.Cipher.Payload != "" {
		ciph, err := base64.StdEncoding.DecodeString(v2.Cipher.Payload)
		if err != nil {
			return nil, false, err
		}
		plain, err := ageDecryptBytes(ciph, identity)
		if err == nil {
			return plain, true, nil
		}
		// Не смогли — но формат валиден
		return nil, false, nil
	}
	// На всякий случай — как старый формат (один из блоков подойдёт)
	var old CipherOld
	if err := yaml.Unmarshal(b, &old); err == nil && len(old.Cipher) > 0 {
		for _, entry := range old.Cipher {
			ciph, err := base64.StdEncoding.DecodeString(entry.Secret)
			if err != nil {
				continue
			}
			plain, err := ageDecryptBytes(ciph, identity)
			if err == nil {
				return plain, true, nil
			}
		}
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("unrecognized cipher file format")
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

/*** SSH identity discovery ***/

func mustLoadSSHIdentity() age.Identity {
	keyPath, err := findSSHIdentityPath()
	must(err)
	keyBytes, err := os.ReadFile(keyPath)
	must(err)

	ident, err := agessh.ParseIdentity(keyBytes)
	if err == nil {
		return ident
	}
	//if errors.Is(err, agessh.ErrIncorrectPassphrase) || strings.Contains(err.Error(), "passphrase") {
	//	fatal("SSH key %s is passphrase-protected; passphrase prompt not supported in this minimal build", keyPath)
	//}
	fatal("parse SSH identity %s: %v", keyPath, err)
	return nil
}

func findSSHIdentityPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	sshDir := filepath.Join(home, ".ssh")

	// 1) ~/.ssh/config → первая IdentityFile
	cfgPath := filepath.Join(sshDir, "config")
	if b, err := os.ReadFile(cfgPath); err == nil {
		if p := firstIdentityFileFromConfig(string(b)); p != "" {
			pp := expandTilde(p, home)
			if isUsableEd25519Key(pp) {
				return pp, nil
			}
		}
	}

	// 2) стандартный id_ed25519
	candidate := filepath.Join(sshDir, "id_ed25519")
	if isUsableEd25519Key(candidate) {
		return candidate, nil
	}

	// 3) скан ~/.ssh на OPENSSH ed25519
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".pub") {
			continue
		}
		path := filepath.Join(sshDir, name)
		if isUsableEd25519Key(path) {
			return path, nil
		}
	}
	return "", fmt.Errorf("no usable ed25519 SSH identity found in %s", sshDir)
}

func firstIdentityFileFromConfig(cfg string) string {
	re := regexp.MustCompile(`(?i)^\s*IdentityFile\s+(.+)\s*$`)
	lines := strings.Split(cfg, "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		m := re.FindStringSubmatch(ln)
		if len(m) == 2 {
			p := strings.Trim(m[1], `"`)
			return p
		}
	}
	return ""
}

func expandTilde(p, home string) string {
	if strings.HasPrefix(p, "~") {
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}

func isUsableEd25519Key(privPath string) bool {
	b, err := os.ReadFile(privPath)
	if err != nil {
		return false
	}
	if !bytes.Contains(b, []byte(openSSHPEMStart)) {
		return false
	}
	pub := privPath + ".pub"
	pb, err := os.ReadFile(pub)
	if err != nil {
		return false
	}
	return bytes.HasPrefix(bytes.TrimSpace(pb), []byte("ssh-ed25519 "))
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
