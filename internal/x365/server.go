package x365

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var nextConnID uint64

type ServerConfig struct {
	Node             Node
	Material         []byte
	Timeout          time.Duration
	HandshakeTimeout time.Duration
	Logf             func(format string, args ...any)
	OnConnection     func(ConnectionEvent)
}

var openX365MultipathFunc = openX365Multipath

type ConnectionEventType int

const (
	ConnectionOpened ConnectionEventType = iota
	ConnectionClosed
	ConnectionUpdated
)

type ConnectionEvent struct {
	ID        uint64
	Type      ConnectionEventType
	From      string
	To        string
	StartedAt time.Time
	ClosedAt  time.Time
	Stats     *ConnectionStats
}

type ConnectionStats struct {
	upload   atomic.Int64
	download atomic.Int64
}

func (s *ConnectionStats) AddUpload(n int64) {
	if s != nil && n > 0 {
		s.upload.Add(n)
	}
}

func (s *ConnectionStats) AddDownload(n int64) {
	if s != nil && n > 0 {
		s.download.Add(n)
	}
}

func (s *ConnectionStats) Upload() int64 {
	if s == nil {
		return 0
	}
	return s.upload.Load()
}

func (s *ConnectionStats) Download() int64 {
	if s == nil {
		return 0
	}
	return s.download.Load()
}

func ServeSOCKS(ctx context.Context, listen string, cfg ServerConfig) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	return ServeSOCKSListener(ctx, ln, cfg)
}

// ServeSOCKSListener is ServeSOCKS with a caller-supplied listener. It lets
// the CLI bind the port first, report the actual address, and fail cleanly if
// the port is already in use.
func ServeSOCKSListener(ctx context.Context, ln net.Listener, cfg ServerConfig) error {
	return serveSOCKS(ctx, ln, cfg)
}

func serveSOCKS(ctx context.Context, ln net.Listener, cfg ServerConfig) error {
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			if err := handleSOCKSConn(ctx, conn, cfg); err != nil {
				if isBenignClientError(err) {
					return
				}
				cfg.logf("[efanadp] client failed: %v", err)
			}
		}()
	}
}

func handleSOCKSConn(ctx context.Context, client net.Conn, cfg ServerConfig) error {
	defer client.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-done:
		}
	}()
	defer close(done)

	id := atomic.AddUint64(&nextConnID, 1)
	from := client.RemoteAddr().String()
	start := time.Now()

	reader := bufio.NewReader(client)
	if cfg.HandshakeTimeout > 0 {
		_ = client.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	}
	if err := socksHandshake(reader, client); err != nil {
		return fmt.Errorf("SOCKS5 handshake: %w", err)
	}
	host, port, err := socksReadConnect(reader, client)
	if err != nil {
		return fmt.Errorf("SOCKS5 request: %w", err)
	}
	if isFakeIPHost(host) {
		_ = writeSocksReply(client, 4)
		return fmt.Errorf("SOCKS5 request got mihomo fake-ip %s; use socks5h:// so the proxy receives the domain", host)
	}
	if cfg.HandshakeTimeout > 0 {
		_ = client.SetDeadline(time.Time{})
	}

	target := net.JoinHostPort(host, fmt.Sprint(port))
	displayTarget := &connectionTarget{to: target}
	connStats := &ConnectionStats{}
	finishConnection := func(finalTarget string, stats relayStats, err error) {
		if err != nil {
			cfg.logf("[tcp #%d] close from=%s to=%s time=%s up=%s down=%s err=%v", id, from, finalTarget, shortDuration(time.Since(start)), formatBytes(stats.Upload), formatBytes(stats.Download), err)
		} else {
			cfg.logf("[tcp #%d] close from=%s to=%s time=%s up=%s down=%s", id, from, finalTarget, shortDuration(time.Since(start)), formatBytes(stats.Upload), formatBytes(stats.Download))
		}
		cfg.emitConnection(ConnectionEvent{
			ID:        id,
			Type:      ConnectionClosed,
			From:      from,
			To:        finalTarget,
			StartedAt: start,
			ClosedAt:  time.Now(),
			Stats:     connStats,
		})
	}
	cfg.logf("[tcp #%d] open from=%s to=%s", id, from, target)
	cfg.emitConnection(ConnectionEvent{
		ID:        id,
		Type:      ConnectionOpened,
		From:      from,
		To:        target,
		StartedAt: start,
		Stats:     connStats,
	})

	upstream, err := cfg.dialMultipath(ctx, host, port)
	if err != nil {
		_ = writeSocksReply(client, 5)
		finishConnection(target, relayStats{Upload: connStats.Upload(), Download: connStats.Download()}, err)
		return nil
	}
	defer upstream.Close()
	upstreamDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = upstream.Close()
		case <-upstreamDone:
		}
	}()
	defer close(upstreamDone)

	_ = writeSocksReply(client, 0)
	var observeUpload func([]byte)
	if sniffer := newShadowsocksTargetSniffer(cfg.Node.shadowsocksSniffConfigs, host, port); sniffer != nil {
		observeUpload = func(p []byte) {
			innerTarget, ok := sniffer.Observe(p)
			if !ok {
				return
			}
			nextTarget := formatTargetChain(target, innerTarget)
			if !displayTarget.set(nextTarget) {
				return
			}
			cfg.logf("[tcp #%d] update from=%s to=%s", id, from, nextTarget)
			cfg.emitConnection(ConnectionEvent{
				ID:        id,
				Type:      ConnectionUpdated,
				From:      from,
				To:        nextTarget,
				StartedAt: start,
				Stats:     connStats,
			})
		}
	}
	stats, err := relayMultipath(&bufferedConn{Conn: client, reader: reader}, upstream, connStats, observeUpload)
	if err != nil {
		finishConnection(displayTarget.get(), stats, err)
		return nil
	}
	finishConnection(displayTarget.get(), stats, nil)
	return nil
}

type connectionTarget struct {
	mu sync.RWMutex
	to string
}

func (t *connectionTarget) get() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.to
}

func (t *connectionTarget) set(to string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.to == to {
		return false
	}
	t.to = to
	return true
}

func (cfg ServerConfig) logf(format string, args ...any) {
	if cfg.Logf == nil {
		return
	}
	cfg.Logf(format, args...)
}

func (cfg ServerConfig) emitConnection(event ConnectionEvent) {
	if cfg.OnConnection == nil {
		return
	}
	cfg.OnConnection(event)
}

func (cfg ServerConfig) dialMultipath(ctx context.Context, destHost string, destPort int) (io.ReadWriteCloser, error) {
	return openX365MultipathFunc(ctx, cfg, destHost, destPort)
}

// Dial opens an X365 stream to destHost:destPort through this node. The caller
// owns the returned connection and must close it.
func (cfg ServerConfig) Dial(ctx context.Context, destHost string, destPort int) (io.ReadWriteCloser, error) {
	return cfg.dialMultipath(ctx, destHost, destPort)
}

func isBenignClientError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if strings.Contains(err.Error(), "http2: response body closed") {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func shortDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KiB", "MiB", "GiB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fTiB", value/unit)
}
