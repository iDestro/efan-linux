package x365

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// ProbeNode opens a tunnel to targetHost:targetPort through node, sends a
// minimal HTTP request, and waits for the response status line. Any HTTP status
// counts as reachable; the returned duration includes the REALITY/X365
// handshake. It is safe to call concurrently for different nodes.
func ProbeNode(ctx context.Context, node Node, material []byte, targetHost string, targetPort int, timeout time.Duration) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if targetHost == "" {
		targetHost = "example.com"
	}
	if targetPort == 0 {
		targetPort = 80
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cfg := ServerConfig{
		Node:             node,
		Material:         material,
		Timeout:          timeout,
		HandshakeTimeout: timeout,
	}
	conn, err := cfg.Dial(ctx, targetHost, targetPort)
	if err != nil {
		return 0, fmt.Errorf("dial %s:%d: %w", targetHost, targetPort, err)
	}

	type probeResult struct {
		latency time.Duration
		err     error
	}
	done := make(chan probeResult, 1)
	go func() {
		request := "GET / HTTP/1.1\r\nHost: " + targetHost +
			"\r\nUser-Agent: efan-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
		if _, err := io.WriteString(conn, request); err != nil {
			done <- probeResult{err: fmt.Errorf("write request: %w", err)}
			return
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			done <- probeResult{err: fmt.Errorf("read response: %w", err)}
			return
		}
		if !strings.HasPrefix(strings.TrimSpace(line), "HTTP/") {
			done <- probeResult{err: fmt.Errorf("unexpected response %q", strings.TrimSpace(line))}
			return
		}
		done <- probeResult{latency: time.Since(start)}
	}()

	select {
	case <-ctx.Done():
		closeProbeConn(conn)
		return 0, ctx.Err()
	case result := <-done:
		closeProbeConn(conn)
		return result.latency, result.err
	}
}

func closeProbeConn(conn io.Closer) {
	done := make(chan struct{})
	go func() {
		_ = conn.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}
