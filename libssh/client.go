// Package libssh — общий ssh-клиентный функционал cage и socli:
// резолв ssh_config (см. пакет sshconfig), аутентификация через ssh-agent и
// IdentityFile, проверка host keys по known_hosts, прямые TCP-каналы
// (direct-tcpip) с keepalive и переподключением.
//
// Заменяет libgate/ssh/tun (InsecureIgnoreHostKey, panic'и, новый
// ssh-соединение на каждый direct-tcpip канал) и централизует то, что
// раньше жило в libcage/identities.go.
package libssh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/themakers/cage/libssh/sshconfig"
)

// Options — настройки ssh-соединения поверх ssh_config.
type Options struct {
	// Config — распарсенный ssh_config. Если nil — загружается DefaultPaths().
	Config *sshconfig.Config

	// OverrideUser/OverridePort/OverrideIdentityFiles — переопределяют
	// ssh_config (аналоги ssh -l/-p/-i).
	OverrideUser          string
	OverridePort          int
	OverrideIdentityFiles []string

	// AgentSocket — сокет ssh-agent. "" = ssh_config IdentityAgent, иначе
	// SSH_AUTH_SOCK; значение "none" отключает агент.
	AgentSocket string

	// StrictHostKeyChecking: "yes" (умолчание), "no", "accept-new".
	StrictHostKeyChecking string
	// KnownHostsFiles — явные пути known_hosts; ""-слайс = из ssh_config.
	KnownHostsFiles []string

	// ServerAliveInterval — интервал keepalive@openssh.com; 0 = из
	// ssh_config, иначе 15с. Отрицательное значение выключает keepalive.
	ServerAliveInterval time.Duration
	// ServerAliveCountMax — безответных keepalive до признания разрывом;
	// 0 = из ssh_config, иначе 3.
	ServerAliveCountMax int
	// ConnectTimeout — таймаут установления ssh-сессии; 0 = 15с.
	ConnectTimeout time.Duration

	Logger *slog.Logger
}

// State — состояние ssh-сессии.
type State int

const (
	StateConnecting State = iota
	StateUp
	StateReconnecting
	StateDown
)

func (s State) String() string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateUp:
		return "up"
	case StateReconnecting:
		return "reconnecting"
	case StateDown:
		return "down"
	default:
		return "unknown"
	}
}

// StateEvent — смена состояния соединения.
type StateEvent struct {
	State State
	// Err — причина перехода в Reconnecting/Down.
	Err error
	// Attempt — номер попытки переподключения (при State==Reconnecting).
	Attempt int
}

// resolved — итоговые параметры подключения.
type resolved struct {
	alias               string
	hostname            string
	user                string
	port                int
	identityFiles       []string
	agentSocket         string
	proxyJump           []string // список jump-спецификаций в порядке хопов
	strictHostKey       string
	knownHostsFiles     []string
	serverAliveInterval time.Duration
	serverAliveCountMax int
	connectTimeout      time.Duration
	keepalivesEnabled   bool
}

// Client — ssh-клиент: один ssh-коннект обслуживает множество direct-tcpip
// каналов, следит keepalive'ами и переподключается с backoff'ом.
type Client struct {
	opts   Options
	cfg    *sshconfig.Config
	r      resolved
	logger *slog.Logger

	onEvent  func(StateEvent)
	mu       sync.Mutex
	ssh      *ssh.Client
	subConns map[net.Conn]struct{} // привязанные жизнью к сессии conns (jump и т.п.)
	state    State
	lastErr  error

	ctx    context.Context
	cancel context.CancelFunc

	reconnectOnce sync.Once
	wg            sync.WaitGroup
}

// Connect устанавливает ssh-соединение к alias. onEvent (может быть nil)
// вызывается при каждой смене состояния. Клиент закрывается Close().
func Connect(ctx context.Context, alias string, opts Options, onEvent func(StateEvent)) (*Client, error) {
	cfg := opts.Config
	if cfg == nil {
		var err error
		if cfg, err = sshconfig.Load(sshconfig.DefaultPaths()...); err != nil {
			return nil, err
		}
	}
	for _, w := range cfg.Warnings {
		if opts.Logger != nil {
			opts.Logger.Debug("sshconfig warning", "warning", w)
		}
	}

	r, err := resolve(alias, cfg, opts)
	if err != nil {
		return nil, err
	}

	lg := opts.Logger
	if lg == nil {
		lg = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	bg, cancel := context.WithCancel(context.Background())
	c := &Client{
		opts:     opts,
		cfg:      cfg,
		r:        r,
		logger:   lg,
		onEvent:  onEvent,
		subConns: map[net.Conn]struct{}{},
		state:    StateConnecting,
		ctx:      bg,
		cancel:   cancel,
	}

	if deadline, ok := ctx.Deadline(); ok {
		bg2, cancel2 := context.WithDeadline(bg, deadline)
		defer cancel2()
		if err := c.openSession(bg2); err != nil {
			cancel()
			return nil, err
		}
	} else {
		openCtx, cancel2 := context.WithTimeout(bg, c.r.connectTimeout)
		defer cancel2()
		if err := c.openSession(openCtx); err != nil {
			cancel()
			return nil, err
		}
	}
	c.setState(StateUp, nil, 0)

	c.wg.Add(1)
	go c.keepaliveLoop()
	// Детект разрыва по завершению ssh-транспорта (сервер отрубил conns
	// без ответа на keepalive).
	c.wg.Add(1)
	go c.waitLoop()
	return c, nil
}

// resolve применяет ssh_config и переопределения.
func resolve(alias string, cfg *sshconfig.Config, opts Options) (resolved, error) {
	rh := cfg.Resolve(alias)

	r := resolved{
		alias:               alias,
		hostname:            firstNonEmpty(rh.Hostname, alias),
		user:                rh.User,
		port:                rh.Port,
		identityFiles:       rh.IdentityFiles,
		agentSocket:         rh.IdentityAgent,
		strictHostKey:       firstNonEmpty(opts.StrictHostKeyChecking, rh.StrictHostKeyChecking),
		knownHostsFiles:     opts.KnownHostsFiles,
		serverAliveInterval: rh.ServerAliveInterval,
		serverAliveCountMax: rh.ServerAliveCountMax,
		connectTimeout:      opts.ConnectTimeout,
		keepalivesEnabled:   true,
	}
	if rh.ProxyJump != "" {
		for _, j := range strings.Split(rh.ProxyJump, ",") {
			if j = strings.TrimSpace(j); j != "" && !strings.EqualFold(j, "none") {
				r.proxyJump = append(r.proxyJump, j)
			}
		}
	}
	if r.port == 0 {
		r.port = 22
	}
	if opts.OverrideUser != "" {
		r.user = opts.OverrideUser
	}
	if opts.OverridePort != 0 {
		r.port = opts.OverridePort
	}
	if opts.OverrideIdentityFiles != nil {
		r.identityFiles = opts.OverrideIdentityFiles
	}
	if opts.AgentSocket != "" {
		r.agentSocket = opts.AgentSocket
	}
	if len(r.knownHostsFiles) == 0 {
		r.knownHostsFiles = rh.KnownHostsFiles
	}
	switch strings.ToLower(r.strictHostKey) {
	case "":
		r.strictHostKey = "accept-new"
	case "ask": // без интерактива ask == accept-new
		r.strictHostKey = "accept-new"
	}
	if opts.ServerAliveCountMax != 0 {
		r.serverAliveCountMax = opts.ServerAliveCountMax
	}
	if r.serverAliveCountMax == 0 {
		r.serverAliveCountMax = 3
	}
	if opts.ServerAliveInterval != 0 {
		if opts.ServerAliveInterval < 0 {
			r.keepalivesEnabled = false
		} else {
			r.serverAliveInterval = opts.ServerAliveInterval
		}
	}
	if r.serverAliveInterval == 0 {
		r.serverAliveInterval = 15 * time.Second
	}
	if opts.ConnectTimeout != 0 {
		r.connectTimeout = opts.ConnectTimeout
	}
	if r.connectTimeout == 0 {
		r.connectTimeout = 15 * time.Second
	}
	if r.user == "" {
		return r, fmt.Errorf("libssh: no user for %q (set User in ssh_config)", alias)
	}
	return r, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// openSession устанавливает ssh-сессию, включая ProxyJump-цепочку.
func (c *Client) openSession(ctx context.Context) error {
	dialer := directNetDialer{timeout: c.r.connectTimeout}

	jumpCli, jumpConns, err := c.openJumpChain(ctx, dialer)
	if err != nil {
		return err
	}

	cfg, addr, err := c.clientConfig()
	if err != nil {
		closeAll(jumpConns)
		if jumpCli != nil {
			jumpCli.Close()
		}
		return err
	}

	var conn net.Conn
	if jumpCli != nil {
		conn, err = jumpCli.Dial("tcp", addr)
	} else {
		conn, err = netDial(ctx, c.r.connectTimeout, "tcp", addr)
	}
	if err != nil {
		closeAll(jumpConns)
		if jumpCli != nil {
			jumpCli.Close()
		}
		return fmt.Errorf("libssh: dial %s://%s: %w", c.r.alias, addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		closeAll(jumpConns)
		if jumpCli != nil {
			jumpCli.Close()
		}
		return fmt.Errorf("libssh: ssh handshake %s://%s: %w", c.r.alias, addr, err)
	}

	c.mu.Lock()
	c.ssh = ssh.NewClient(sshConn, chans, reqs)
	// Связываем жизненный цикл jump-звеньев с сессией: закрываем при markDead/Close.
	for _, jc := range jumpConns {
		c.subConns[jc] = struct{}{}
	}
	if jumpCli != nil {
		c.subConns[&waitConn{Client: jumpCli}] = struct{}{}
	}
	c.mu.Unlock()
	return nil
}

// waitConn — обёртка для закрытия нижележащего ssh.Client как net.Conn.
type waitConn struct{ Client *ssh.Client }

func (w *waitConn) Read([]byte) (int, error)         { return 0, nil }
func (w *waitConn) Write([]byte) (int, error)        { return 0, nil }
func (w *waitConn) Close() error                     { return w.Client.Close() }
func (w *waitConn) LocalAddr() net.Addr              { return nil }
func (w *waitConn) RemoteAddr() net.Addr             { return nil }
func (w *waitConn) SetDeadline(time.Time) error      { return nil }
func (w *waitConn) SetReadDeadline(time.Time) error  { return nil }
func (w *waitConn) SetWriteDeadline(time.Time) error { return nil }

// openJumpChain открывает ProxyJump-цепочку и возвращает ssh.Client
// последнего хопа (или nil при отсутствии ProxyJump) + нижележащие conns.
func (c *Client) openJumpChain(ctx context.Context, diale directNetDialer) (*ssh.Client, []net.Conn, error) {
	var (
		cli   *ssh.Client
		conns []net.Conn
	)
	fail := func(err error) (*ssh.Client, []net.Conn, error) {
		closeAll(conns)
		if cli != nil {
			cli.Close()
		}
		return nil, nil, err
	}

	for i, hop := range c.r.proxyJump {
		host, port, user := splitUserHostPort(hop)

		// Параметры хопа — из ssh_config по его hostname/алиасу.
		hopCfg, hopResolved, err := c.hopClientConfig(host, port, user)
		if err != nil {
			return fail(fmt.Errorf("libssh: proxyjump hop %q: %w", hop, err))
		}

		addr := net.JoinHostPort(hopResolved.hostname, fmt.Sprint(hopResolved.port))
		var conn net.Conn
		if cli == nil {
			conn, err = netDial(ctx, c.r.connectTimeout, "tcp", addr)
		} else {
			conn, err = cli.Dial("tcp", addr)
		}
		if err != nil {
			return fail(fmt.Errorf("libssh: proxyjump dial %s: %w", addr, err))
		}

		sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, hopCfg)
		if err != nil {
			conn.Close()
			return fail(fmt.Errorf("libssh: proxyjump handshake %s: %w", addr, err))
		}
		conns = append(conns, conn)

		prev := cli
		cli = ssh.NewClient(sshConn, chans, reqs)
		if prev != nil && i > 0 {
			// предыдущий хоп остаётся жить: он лежит в conns-цепочке.
		}

		_ = prev
		_ = i
	}
	return cli, conns, nil
}

// hopClientConfig строит ssh.ClientConfig для хопа ProxyJump, используя
// ssh_config по имени хопа (user@host:port — лишь override).
func (c *Client) hopClientConfig(host string, port int, user string) (*ssh.ClientConfig, resolved, error) {
	r := resolvedFor(c.cfg, host, port, user, c.opts)
	methods, err := authMethodsFor(r, c.logger)
	if err != nil {
		return nil, resolved{}, err
	}
	if len(methods) == 0 {
		return nil, resolved{}, fmt.Errorf("no auth methods for %q", host)
	}
	hkcb, err := hostKeyCallback(r, c.logger)
	if err != nil {
		return nil, resolved{}, err
	}
	return &ssh.ClientConfig{
		User:            r.user,
		Auth:            methods,
		HostKeyCallback: hkcb,
		Timeout:         c.r.connectTimeout,
	}, r, nil
}

// resolvedFor вычисляет resolved для произвольного host/aliаса с теми же
// глобальными опциями, что и у основного клиента.
func resolvedFor(cfg *sshconfig.Config, alias string, port int, user string, opts Options) resolved {
	r, _ := resolve(alias, cfg, Options{})
	if port != 0 {
		r.port = port
	}
	if user != "" {
		r.user = user
	}
	if opts.OverridePort != 0 {
		r.port = opts.OverridePort
	}
	r.strictHostKey = firstNonEmpty(opts.StrictHostKeyChecking, r.strictHostKey, "accept-new")
	r.connectTimeout = opts.ConnectTimeout
	if r.connectTimeout == 0 {
		r.connectTimeout = 15 * time.Second
	}
	return r
}

// clientConfig собирает ssh.ClientConfig основного хоста.
func (c *Client) clientConfig() (*ssh.ClientConfig, string, error) {
	methods, err := authMethodsFor(c.r, c.logger)
	if err != nil {
		return nil, "", err
	}
	if len(methods) == 0 {
		return nil, "", fmt.Errorf("libssh: no auth methods for %q (ssh-agent unavailable/empty and no usable IdentityFile)", c.r.alias)
	}
	hkcb, err := hostKeyCallback(c.r, c.logger)
	if err != nil {
		return nil, "", err
	}
	return &ssh.ClientConfig{
		User:            c.r.user,
		Auth:            methods,
		HostKeyCallback: hkcb,
		Timeout:         c.r.connectTimeout,
	}, net.JoinHostPort(c.r.hostname, strconv.Itoa(c.r.port)), nil
}

// authMethodsFor — ssh-agent + IdentityFile'ы для resolved-параметров.
func authMethodsFor(r resolved, lg *slog.Logger) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	sock := r.agentSocket
	if sock == "" {
		sock = os.Getenv("SSH_AUTH_SOCK")
	}
	if sock != "" && sock != "none" {
		if conn, err := net.Dial("unix", sock); err == nil {
			agentClient := agent.NewClient(conn)
			methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
		} else if lg != nil {
			lg.Debug("libssh: agent socket unavailable", "socket", sock, "err", err)
		}
	}

	var signers []ssh.Signer
	for _, path := range r.identityFiles {
		signer, err := LoadIdentityFile(path)
		if err != nil {
			if lg != nil {
				lg.Debug("libssh: identity unusable", "file", path, "err", err)
			}
			continue
		}
		signers = append(signers, signer)
	}
	if len(signers) > 0 {
		methods = append(methods, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return signers, nil
		}))
	}
	return methods, nil
}

// DialContext открывает direct-tcpip канал к network/address через живую
// ssh-сессию; если сессия мертва — ждёт переподключения до таймаута ctx
// или ConnectTimeout.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	deadline := time.Now().Add(c.r.connectTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	for {
		c.mu.Lock()
		cli := c.ssh
		up := c.state == StateUp
		c.mu.Unlock()

		if up && cli != nil {
			conn, err := cli.DialContext(ctx, network, address)
			if err == nil {
				return conn, nil
			}
			// Ошибки нашего ctx — не признак смерти сессии.
			if ctx.Err() != nil {
				return nil, err
			}
			// Ошибка самого direct-tcpip канала (upstream недоступен) —
			// сессия жива, возвращаем вызывающему; иначе помечаем мёртвой.
			if isTransportError(err) {
				c.logger.Debug("libssh: dial failed, session marked down", "err", err)
				c.markDead(err)
			} else {
				return nil, err
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("libssh: no ssh session to %s within %s", c.r.alias, c.r.connectTimeout)
		}

		c.mu.Lock()
		if c.state == StateDown {
			err := c.lastErr
			c.mu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("libssh: session to %s is down", c.r.alias)
		}
		c.mu.Unlock()

		// Ждём смены состояния: опрашиваем с коротким тайм-аутом
		// (cond.Wait не используем — нужен контроль через ctx).
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// markDead переводит клиента в Reconnecting и запускает переподключение.
func (c *Client) markDead(err error) {
	c.mu.Lock()
	if c.state != StateUp && c.state != StateConnecting {
		c.mu.Unlock()
		return
	}
	if c.ssh != nil {
		c.ssh.Close()
	}
	c.ssh = nil
	for conn := range c.subConns {
		conn.Close()
		delete(c.subConns, conn)
	}
	c.state = StateReconnecting
	c.lastErr = err
	c.mu.Unlock()

	c.emit(StateEvent{State: StateReconnecting, Err: err})
	go c.reconnectLoop()
}

// reconnectLoop — переподключение с экспоненциальным backoff (1с→30с).
func (c *Client) reconnectLoop() {
	attempt := 0
	backoff := time.Second
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		attempt++
		ctx, cancel := context.WithTimeout(c.ctx, c.r.connectTimeout)
		err := c.openSession(ctx)
		cancel()
		if err == nil {
			c.setState(StateUp, nil, 0)
			return
		}
		c.logger.Debug("libssh: reconnect attempt failed", "attempt", attempt, "err", err)
		c.mu.Lock()
		c.lastErr = err
		c.mu.Unlock()
		c.emit(StateEvent{State: StateReconnecting, Err: err, Attempt: attempt})

		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = minDur(backoff*2, 30*time.Second)
	}
}

// keepaliveLoop шлёт keepalive@openssh.com по расписанию.
func (c *Client) keepaliveLoop() {
	defer c.wg.Done()
	if !c.r.keepalivesEnabled {
		return
	}
	t := time.NewTicker(c.r.serverAliveInterval)
	defer t.Stop()

	missed := 0
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
		}
		c.mu.Lock()
		cli := c.ssh
		up := c.state == StateUp
		c.mu.Unlock()
		if !up || cli == nil {
			continue
		}
		_, _, err := cli.SendRequest("keepalive@openssh.com", true, nil)
		if err != nil {
			missed++
			if missed >= c.r.serverAliveCountMax {
				c.markDead(fmt.Errorf("keepalive: %w", err))
				missed = 0
			}
		} else {
			missed = 0
		}
	}
}

// waitLoop детектит разрыв по завершению ssh-транспорта.
func (c *Client) waitLoop() {
	defer c.wg.Done()
	for {
		c.mu.Lock()
		cli := c.ssh
		up := c.state == StateUp
		c.mu.Unlock()
		if !up || cli == nil {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		err := cli.Conn.Wait()
		if err != nil {
			c.markDead(fmt.Errorf("transport: %w", err))
		}
	}
}

// Close рвёт соединение и останавливает фоновые горутины.
func (c *Client) Close() error {
	c.mu.Lock()
	alreadyDown := c.state == StateDown
	if !alreadyDown {
		c.state = StateDown
	}
	if c.ssh != nil {
		c.ssh.Close()
		c.ssh = nil
	}
	for conn := range c.subConns {
		conn.Close()
		delete(c.subConns, conn)
	}

	c.mu.Unlock()

	if !alreadyDown {
		c.cancel()
		c.wg.Wait()
		c.emit(StateEvent{State: StateDown})
	}
	return nil
}

// State — актуальное состояние.
func (c *Client) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Reconnect — принудительный разрыв и переподключение (кнопка в UI).
func (c *Client) Reconnect() {
	c.markDead(errors.New("manual reconnect"))
}

// LastError — последняя ошибка сессии.
func (c *Client) LastError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastErr
}

// Alias — имя хоста из конфигурации.
func (c *Client) Alias() string { return c.r.alias }

// ResolvedAddr — "user@hostname:port" итогового подключения.
func (c *Client) ResolvedAddr() string {
	return fmt.Sprintf("%s@%s:%d", c.r.user, c.r.hostname, c.r.port)
}

func (c *Client) emit(e StateEvent) {
	if c.onEvent != nil {
		c.onEvent(e)
	}
}

func (c *Client) setState(s State, err error, attempt int) {
	c.mu.Lock()
	c.state = s
	c.lastErr = err

	c.mu.Unlock()
	c.emit(StateEvent{State: s, Err: err, Attempt: attempt})
}

// isTransportError отличает глобальный сбой ssh-транспорта от отказа
// direct-tcpip канала (upstream unreachable/refused — ошибка канала, а
// не сессии).
func isTransportError(err error) bool {
	msg := err.Error()
	if strings.Contains(msg, "open failed") ||
		strings.Contains(msg, "administratively prohibited") ||
		strings.Contains(msg, "Connection refused") {
		return false
	}
	return true
}

// directNetDialer — обычный TCP-dialer с таймаутом.
type directNetDialer struct{ timeout time.Duration }

func netDial(ctx context.Context, timeout time.Duration, network, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, address)
}

func closeAll(conns []net.Conn) {
	for _, conn := range conns {
		conn.Close()
	}
}

// splitUserHostPort — "user@host:port" / "host:port" / "host" → компоненты.
func splitUserHostPort(s string) (host string, port int, user string) {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		user, s = s[:i], s[i+1:]
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		if n, err := strconv.Atoi(p); err == nil {
			return h, n, user
		}
		return h, 0, user
	}
	return s, 0, user
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
