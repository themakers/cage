// Package sshconfig — парсер OpenSSH client configuration files (~/.ssh/config).
//
// За основу взят libgate/ssh/ssh_config (raw.go), доработанный до честного
// подмножества семантики OpenSSH:
//
//   - Host-блоки с несколькими паттернами в строке, glob * ? и негацией !;
//   - ссылочная семантика "первое полученное значение побеждает" по порядку
//     файла (IdentityFile — исключение, аккумулируется);
//   - Include: рекурсивный, с глобами, относительные пути от ~/.ssh для
//     пользовательского конфига (как OpenSSH), глубина ограничена;
//   - каскад user config -> system config в этом порядке;
//   - token expansion (%h %p %r %u %d %%) в Hostname/IdentityFile/IdentityAgent/
//     ProxyJump, а также ~/ и ${ENV};
//   - Match-блоки не поддерживаются: пропускаются с записью в Warnings.
//
// Неизвестные опции не вызывают ошибок (соответствует IgnoreUnknown и
// устойчивости к опциям, специфичным для других платформ, напр. UseKeychain).
package sshconfig

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// SystemWidePath — системный конфиг OpenSSH.
	SystemWidePath = "/etc/ssh/ssh_config"
	// UserPathSuffix — путь пользовательского конфига относительно home.
	UserPathSuffix = ".ssh/config"

	maxIncludeDepth = 16
)

// DefaultPaths — стандартный каскад: сначала пользовательский, потом
// системный (каскад в этом порядке, семантика "first obtained value wins").
func DefaultPaths() []string {
	paths := []string{}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, UserPathSuffix))
	}
	return append(paths, SystemWidePath)
}

type optionEntry struct {
	key   string // lowercase
	value string
	src   string // file:line
}

type hostBlock struct {
	patterns []string // префикс "!" — негативный паттерн
	match    bool     // Match-блок: не поддерживаем, опции игнорируются
	entries  []optionEntry
}

// Config — распарсенный ssh client config.
type Config struct {
	blocks []hostBlock

	// Warnings — нефатальные замечания при парсинге (например, Match-блоки).
	Warnings []string

	home string
}

// Load парсит существующие файлы из paths в указанном порядке. Отсутствующие
// файлы пропускаются; ошибки чтения/парсинга — фатальны.
func Load(paths ...string) (*Config, error) {
	c := &Config{}
	if home, err := os.UserHomeDir(); err == nil {
		c.home = home
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if err := c.parseFile(p, filepath.Dir(p), 0); err != nil {
			return nil, fmt.Errorf("sshconfig: %s: %w", p, err)
		}
	}
	return c, nil
}

// Parse парсит один файл (может не существовать в других тестовых сценариях —
// такое использование не предполагает DefaultPaths).
func Parse(path string) (*Config, error) {
	return Load(path)
}

// Merge добавляет блоки other после текущих (сохраняя порядок first-wins).
func (c *Config) Merge(other *Config) {
	c.blocks = append(c.blocks, other.blocks...)
	c.Warnings = append(c.Warnings, other.Warnings...)
}

func (c *Config) parseFile(path, includeBase string, depth int) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("include depth exceeded")
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var blk *hostBlock
	lineNo := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		lineNo++
		src := fmt.Sprintf("%s:%d", path, lineNo)
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.Trim(line, " \t\r")
		if line == "" {
			continue
		}

		key, value, ok := splitOption(line)
		if !ok {
			return fmt.Errorf("%s: unprocessable line: %q", src, line)
		}
		lkey := strings.ToLower(key)

		switch lkey {
		case "host":
			blk = &hostBlock{patterns: fieldsQuoted(value)}
			c.blocks = append(c.blocks, *blk)
		case "match":
			blk = &hostBlock{match: true}
			c.blocks = append(c.blocks, *blk)
			c.Warnings = append(c.Warnings, fmt.Sprintf("%s: Match blocks are unsupported, skipped", src))
		case "include":
			for _, pat := range fieldsQuoted(value) {
				if err := c.include(pat, includeBase, depth, src); err != nil {
					return err
				}
			}
			// Include не сбрасывает текущий Host-блок — директивы после
			// Include относятся к прежнему блоку, как в OpenSSH.
		case "proxyjump":
			fallthrough
		default:
			if blk == nil {
				// Опции до первого Host/Match применяются ко всем хостам
				// (эквивалент Host * в начале файла).
				c.blocks = append(c.blocks, hostBlock{patterns: []string{"*"}})
				blk = &c.blocks[len(c.blocks)-1]
			} else {
				blk = &c.blocks[len(c.blocks)-1]
			}
			if blk.match {
				continue
			}
			blk.entries = append(blk.entries, optionEntry{key: lkey, value: value, src: src})
		}
	}
	return scanner.Err()
}

func (c *Config) include(pat, base string, depth int, src string) error {
	pat = os.ExpandEnv(pat)
	if strings.HasPrefix(pat, "~/") || pat == "~" {
		pat = expandHome(pat, c.home)
	}
	if !filepath.IsAbs(pat) {
		// OpenSSH: относительные пути в пользовательском конфиге — от ~/.ssh,
		// в системном — от /etc/ssh. includeBase передаёт верный каталог
		// извне; для вложенных Include база остаётся исходной.
		pat = filepath.Join(base, pat)
	}
	pat = filepath.Clean(pat)

	matches, err := filepath.Glob(pat)
	if err != nil {
		return fmt.Errorf("%s: bad Include pattern %q: %w", src, pat, err)
	}
	if matches == nil {
		// Несовпавший glob — не ошибка (как в OpenSSH).
		return nil
	}
	for _, m := range matches {
		fi, err := os.Stat(m)
		if err != nil || fi.IsDir() {
			continue
		}
		if err := c.parseFile(m, base, depth+1); err != nil {
			return fmt.Errorf("include %s: %w", m, err)
		}
	}
	return nil
}

// splitOption разбирает "Key value", "Key=value", "Key  value".
func splitOption(line string) (key, value string, ok bool) {
	i := strings.IndexAny(line, " \t=")
	if i <= 0 {
		return "", "", false
	}
	key = line[:i]
	rest := strings.TrimLeftFunc(line[i:], func(r rune) bool {
		return r == ' ' || r == '\t' || r == '='
	})
	if rest == "" {
		return "", "", false
	}
	return key, unquote(rest), true
}

// unquote снимает парные двойные кавычки (OpenSSH допускает quoted strings).
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// fieldsQuoted разбивает список аргументов (Host a b c), сохраняя quoted-части.
func fieldsQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// matchHost проверяет, применим ли блок к alias по правилам Host-паттернов:
// совпадение любого позитивного паттерна и ни одного негативного.
func matchHost(patterns []string, alias string) bool {
	matched := false
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") {
			if globMatch(p[1:], alias) {
				return false
			}
			continue
		}
		if globMatch(p, alias) {
			matched = true
		}
	}
	return matched
}

func globMatch(pat, s string) bool {
	ok, err := filepath.Match(pat, strings.ToLower(s))
	if err != nil {
		// Некорректный glob (например, "["), трактуем как литерал.
		return pat == s
	}
	return ok
}

// first возвращает первое значение опции key среди применимых к alias блоков.
func (c *Config) first(alias, key string) (string, bool) {
	for i := range c.blocks {
		blk := &c.blocks[i]
		if blk.match || !matchHost(blk.patterns, alias) {
			continue
		}
		for _, e := range blk.entries {
			if e.key == key {
				return e.value, true
			}
		}
	}
	return "", false
}

// Get — значение опции для alias с учётом "first obtained value wins".
// Ключ case-insensitive ("hostname", "Hostname", ...).
func (c *Config) Get(alias, key string) string {
	v, _ := c.first(alias, strings.ToLower(key))
	return v
}

// All возвращает все значения опции (для накопительных, напр. IdentityFile),
// дедублицированные, в порядке появления.
func (c *Config) All(alias, key string) []string {
	key = strings.ToLower(key)
	var out []string
	seen := map[string]struct{}{}
	for i := range c.blocks {
		blk := &c.blocks[i]
		if blk.match || !matchHost(blk.patterns, alias) {
			continue
		}
		for _, e := range blk.entries {
			if e.key != key {
				continue
			}
			if _, dup := seen[e.value]; dup {
				continue
			}
			seen[e.value] = struct{}{}
			out = append(out, e.value)
		}
	}
	return out
}

// IdentityFiles — все IdentityFile, объявленные в применимых блоках.
// Полезно для discovery (cage identities) вне контекста конкретного хоста.
func (c *Config) IdentityFiles(alias string) []string {
	return c.All(alias, "identityfile")
}

// Hosts — явные позитивные Host-паттерны (без * и !), присутствующие
// в конфиге. Нужно discovery-в-духе-задачам (перечислить известные алиасы).
func (c *Config) Hosts() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, blk := range c.blocks {
		if blk.match {
			continue
		}
		for _, p := range blk.patterns {
			if strings.HasPrefix(p, "!") || strings.ContainsAny(p, "*?") {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// Resolved — вычисленные параметры подключения к alias.
type Resolved struct {
	Alias string

	Hostname string // default: alias, с token expansion
	User     string // default: текущий пользователь ОС
	Port     int    // default: 22

	IdentityFiles []string // path expansion применено
	IdentityAgent string   // path/ENV-ref, expansion применено; "" = нет
	ProxyJump     string   // как в конфиге (может содержать user@host:port[,...])

	StrictHostKeyChecking string   // "yes"/"no"/"ask"/"accept-new"/"" (умолчание — accept-new)
	KnownHostsFiles       []string // User + Global

	ServerAliveInterval time.Duration // 0 = отключить
	ServerAliveCountMax int           // default 3
	ConnectTimeout      time.Duration // 0 = таймаут платформы
}

// Resolve вычисляет параметры alias с дефолтами и token expansion.
func (c *Config) Resolve(alias string) Resolved {
	r := Resolved{Alias: alias, Port: 22, ServerAliveCountMax: 3}

	localUser := ""
	if u, err := user.Current(); err == nil {
		localUser = u.Username
	}

	hostname := c.Get(alias, "hostname")
	if hostname == "" {
		hostname = alias
	}
	if u := c.Get(alias, "user"); u != "" {
		r.User = u
	} else {
		r.User = localUser
	}
	if p := c.Get(alias, "port"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			r.Port = n
		}
	}

	expand := func(s string) string {
		return expandTokens(s, map[string]string{
			"h": hostname,
			"p": strconv.Itoa(r.Port),
			"r": r.User,
			"u": localUser,
			"d": c.home,
		}, c.home)
	}

	r.Hostname = expand(hostname)
	for _, f := range c.All(alias, "identityfile") {
		r.IdentityFiles = append(r.IdentityFiles, expand(f))
	}
	r.IdentityAgent = expand(c.Get(alias, "identityagent"))
	r.ProxyJump = expand(c.Get(alias, "proxyjump"))
	r.StrictHostKeyChecking = strings.ToLower(c.Get(alias, "stricthostkeychecking"))

	// KnownHostsFiles: UserKnownHostsFile (default ~/.ssh/known_hosts),
	// затем GlobalKnownHostsFile (default /etc/ssh/known_hosts).
	if v := c.Get(alias, "userknownhostsfile"); v != "" {
		for _, f := range strings.Fields(v) {
			r.KnownHostsFiles = append(r.KnownHostsFiles, expand(f))
		}
	} else if c.home != "" {
		r.KnownHostsFiles = append(r.KnownHostsFiles, filepath.Join(c.home, ".ssh", "known_hosts"))
	}
	if v := c.Get(alias, "globalknownhostsfile"); v != "" {
		for _, f := range strings.Fields(v) {
			r.KnownHostsFiles = append(r.KnownHostsFiles, expand(f))
		}
	} else {
		r.KnownHostsFiles = append(r.KnownHostsFiles, "/etc/ssh/known_hosts")
	}

	if v := c.Get(alias, "serveraliveinterval"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			r.ServerAliveInterval = time.Duration(n) * time.Second
		}
	}
	if v := c.Get(alias, "serveralivecountmax"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			r.ServerAliveCountMax = n
		}
	}
	if v := c.Get(alias, "connecttimeout"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			r.ConnectTimeout = time.Duration(n) * time.Second
		}
	}

	return r
}

// expandTokens раскрывает %-токены OpenSSH и ~/ префикс + ${ENV}.
func expandTokens(s string, toks map[string]string, home string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		k := string(s[i+1])
		if k == "%" {
			b.WriteByte('%')
		} else if v, ok := toks[k]; ok {
			b.WriteString(v)
		} else {
			// Неизвестный токен — сохраняем как есть (как OpenSSH).
			b.WriteByte('%')
			b.WriteByte(s[i+1])
		}
		i++
	}
	return expandHome(os.ExpandEnv(b.String()), home)
}

func expandHome(p, home string) string {
	if home == "" {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}
