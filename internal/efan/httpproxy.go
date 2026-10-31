package efan

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// ServeHTTPProxy exposes a small HTTP/CONNECT proxy that dials through the
// local x365 SOCKS5 listener. It exists so GNOME's HTTP/HTTPS proxy settings
// can use the tunnel too; many desktop applications do not understand SOCKS.
func ServeHTTPProxy(ctx context.Context, listen, socksAddr string, logf func(string, ...any)) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	return ServeHTTPProxyListener(ctx, ln, socksAddr, logf)
}

func ServeHTTPProxyListener(ctx context.Context, ln net.Listener, socksAddr string, logf func(string, ...any)) error {
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
			if err := handleHTTPProxyConn(ctx, conn, socksAddr, logf); err != nil {
				logf("[http] error: %v", err)
			}
		}()
	}
}

func handleHTTPProxyConn(ctx context.Context, client net.Conn, socksAddr string, logf func(string, ...any)) error {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	_ = client.SetDeadline(time.Time{})

	if strings.EqualFold(req.Method, http.MethodConnect) {
		target := ensurePort(req.Host, "443")
		logf("[http] CONNECT %s", target)
		upstream, err := dialThroughSOCKS(ctx, socksAddr, target)
		if err != nil {
			_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return fmt.Errorf("CONNECT %s: %w", target, err)
		}
		defer upstream.Close()
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return err
		}
		if br.Buffered() > 0 {
			if _, err := io.CopyN(upstream, br, int64(br.Buffered())); err != nil {
				return err
			}
		}
		relay(client, upstream)
		return nil
	}

	if req.URL == nil || req.URL.Host == "" {
		_, _ = io.WriteString(client, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return errors.New("plain HTTP request without absolute URL")
	}
	hostHeader := req.Host
	if hostHeader == "" {
		hostHeader = req.URL.Host
	}
	target := ensurePort(req.URL.Host, "80")
	logf("[http] %s %s", req.Method, target)
	upstream, err := dialThroughSOCKS(ctx, socksAddr, target)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return fmt.Errorf("%s %s: %w", req.Method, target, err)
	}
	defer upstream.Close()

	req.RequestURI = ""
	req.URL.Scheme = ""
	req.URL.Host = ""
	req.Host = hostHeader
	req.Close = true
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Header.Set("Connection", "close")
	if err := req.Write(upstream); err != nil {
		return fmt.Errorf("write upstream request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return fmt.Errorf("read upstream response: %w", err)
	}
	defer resp.Body.Close()
	resp.Close = true
	if err := resp.Write(client); err != nil {
		return fmt.Errorf("write client response: %w", err)
	}
	return nil
}

func dialThroughSOCKS(ctx context.Context, socksAddr, target string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(target)
	if isLoopbackHost(host) {
		d := net.Dialer{Timeout: 15 * time.Second}
		return d.DialContext(ctx, "tcp", target)
	}
	dialer, err := xproxy.SOCKS5("tcp", socksAddr, nil, xproxy.Direct)
	if err != nil {
		return nil, err
	}
	type contextDialer interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}
	if cd, ok := dialer.(contextDialer); ok {
		return cd.DialContext(ctx, "tcp", target)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := dialer.Dial("tcp", target)
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

func ensurePort(hostport, defaultPort string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return hostport + ":" + defaultPort
	}
	return net.JoinHostPort(hostport, defaultPort)
}

func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		closeWrite(dst)
		closeWrite(src)
	}
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
