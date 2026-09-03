package libssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"
)

// Forward — слушает локальный порт и проксирует каждое входящее
// TCP-соединение в удалённый адрес через ssh-клиент.
//
// Per-connection модель (не один persistent канал): каждый входящий
// conn получает свой direct-tcpip канал, что важно для протоколов
// с per-connection состоянием (MongoDB SCRAM, MySQL auth).
type Forward struct {
	// Name — для логирования/счётчиков.
	Name string
	// Listen — локальный адрес ("127.0.0.1:27017").
	Listen string
	// Network — "tcp" (единственный поддерживаемый сейчас); опционально "tcp4"/"tcp6".
	Network string
	// Remote — целевой address на удалённой стороне ssh ("host:port").
	Remote string

	// WrapUpstream — опциональный хук-обработчик; если не nil, Forward
	// НЕ запускает raw relay, а вызывает WrapUpstream, который сам
	// управляет проксированием (broker для mongo/mysql/http и т.п.).
	WrapUpstream func(ctx context.Context, client net.Conn, upstream net.Conn) error

	Logger *slog.Logger

	// Prebound — если не nil, Run() использует этот listener вместо
	// net.Listen (позволяет вызывающему коду отловить ошибку bind до
	// старта цикла accept).
	Prebound net.Listener

	listener net.Listener

	// Метрики.
	connsActive  atomic.Int64
	connsTotal   atomic.Int64
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64
	lastConnUnix atomic.Int64
}

// MetricsSnapshot — состояние Forward для UI.
type MetricsSnapshot struct {
	Active      int64 // открытых сейчас
	Total       int64 // всего обработано
	BytesUp     int64 // к удалённой стороне
	BytesDown   int64 // от удалённой стороны
	LastConn    time.Time
	HasLastConn bool
}

// Metrics — снимок счётчиков.
func (f *Forward) Metrics() MetricsSnapshot {
	s := MetricsSnapshot{
		Active:    f.connsActive.Load(),
		Total:     f.connsTotal.Load(),
		BytesUp:   f.bytesUp.Load(),
		BytesDown: f.bytesDown.Load(),
	}
	if u := f.lastConnUnix.Load(); u != 0 {
		s.LastConn = time.Unix(u, 0)
		s.HasLastConn = true
	}
	return s
}

// Run держит listener. Завершается по отмене ctx или фатальной ошибке listen.
func (f *Forward) Run(ctx context.Context, dialer Dialer) error {
	lg := f.Logger
	if lg == nil {
		lg = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	network := f.Network
	if network == "" {
		network = "tcp"
		f.Network = network
	}

	go func() { // закрытие по отмене ctx
		<-ctx.Done()
		if f.listener != nil {
			f.listener.Close()
		}
	}()

	var (
		ln  net.Listener
		err error
	)
	if f.Prebound != nil {
		ln = f.Prebound
	} else {
		ln, err = net.Listen(network, f.Listen)
		if err != nil {
			return fmt.Errorf("libssh/forward %s: listen %s: %w", f.Name, f.Listen, err)
		}
	}
	f.listener = ln
	lg = lg.With("forward", f.Name, "listen", f.Listen, "remote", f.Remote)

	lg.Info("forward listening")

	var acceptErr error
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			acceptErr = err
			lg.Error("accept failed", "err", err)
			break
		}

		f.connsActive.Add(1)
		f.connsTotal.Add(1)
		f.lastConnUnix.Store(time.Now().Unix())

		go f.handle(ctx, dialer, conn, lg)
	}
	return acceptErr
}

// handle обрабатывает одно входящее соединение.
func (f *Forward) handle(ctx context.Context, dialer Dialer, client net.Conn, lg *slog.Logger) {
	defer func() {
		f.connsActive.Add(-1)
		client.Close()
	}()

	clg := lg.With("client", client.RemoteAddr().String())

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	upstream, err := dialer.DialContext(dialCtx, f.Network, f.Remote)
	cancel()
	if err != nil {
		clg.Warn("upstream dial failed", "err", err)
		return
	}
	defer upstream.Close()

	if f.WrapUpstream != nil {
		if err := f.WrapUpstream(ctx, client, upstream); err != nil {
			clg.Debug("upstream handler failed", "err", err)
		}
		return
	}

	// Raw relay: полудуплексное копирование, ждём обе стороны.
	relay(f.upCounter(), f.downCounter(), client, upstream)
}

// upCounter/downCounter — io.Writer'ы счётчиков, прикрученные через TeeReader.
func (f *Forward) upCounter() *countWriter   { return &countWriter{n: &f.bytesUp} }
func (f *Forward) downCounter() *countWriter { return &countWriter{n: &f.bytesDown} }

type countWriter struct{ n *atomic.Int64 }

func (w *countWriter) Write(p []byte) (int, error) {
	w.n.Add(int64(len(p)))
	return len(p), nil
}

// relay качает данные в обе стороны с подсчётом байтов. Завершается, когда
// закрылась любая сторона (полудуплексный shutdown не ждём: у нас per-conn
// туннели, и половина протокола после EOF уже не продолжает диалог).
func relay(upW, downW *countWriter, a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader, w *countWriter) {
		_, _ = io.Copy(io.MultiWriter(dst, w), src)
		done <- struct{}{}
	}
	go cp(b, a, upW)
	go cp(a, b, downW)
	<-done
	// Вторую сторону не ждём: обе conns закроются в defer'ах handle.
}

// Dialer — интерфейс для DialContext; реализует *Client.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ListenerPort возвращает порт, на котором слушает Forward (0 — до Run()).
func (f *Forward) ListenerPort() int {
	if f.listener == nil {
		return 0
	}
	if ta, ok := f.listener.Addr().(*net.TCPAddr); ok {
		return ta.Port
	}
	return 0
}

// Addr — адрес listener'а.
func (f *Forward) Addr() net.Addr {
	if f.listener == nil {
		return nil
	}
	return f.listener.Addr()
}

var _ = io.Discard
