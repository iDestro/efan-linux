package x365

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

func openStream(ctx context.Context, node Node, timeout time.Duration) (io.ReadWriteCloser, error) {
	if node.Path == "" {
		return nil, errors.New("node path is empty")
	}
	realityConfig, err := buildRealityConfig(node)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)

	reqURL := url.URL{
		Scheme: "https",
		Host:   node.Host,
		Path:   node.Path,
	}
	if reqURL.Host == "" {
		reqURL.Host = node.SNI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	if node.Host != "" {
		req.Host = node.Host
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("User-Agent", chromeUserAgent)
	if node.Host != "" {
		req.Header.Set("Referer", "https://"+node.Host+node.Path)
	}

	transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			var dialer net.Dialer
			if timeout > 0 {
				dialer.Timeout = timeout
			}
			raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(node.Server, strconv.Itoa(node.Port)))
			if err != nil {
				return nil, fmt.Errorf("tcp dial: %w", err)
			}
			conn, err := dialReality(ctx, raw, realityConfig)
			if err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("reality handshake: %w", err)
			}
			return conn, nil
		},
	}

	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			_ = pr.CloseWithError(err)
			errCh <- fmt.Errorf("http2 post: %w", err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			err := fmt.Errorf("x365 server returned HTTP %d", resp.StatusCode)
			_ = resp.Body.Close()
			_ = pr.CloseWithError(err)
			errCh <- err
			return
		}
		respCh <- resp
	}()

	return &httpStream{
		requestWriter: pw,
		responseCh:    respCh,
		errorCh:       errCh,
		closeIdle:     transport.CloseIdleConnections,
	}, nil
}

const chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

type httpStream struct {
	requestWriter *io.PipeWriter
	responseCh    <-chan *http.Response
	errorCh       <-chan error
	closeIdle     func()

	once sync.Once
	resp *http.Response
	err  error
}

func (s *httpStream) Write(p []byte) (int, error) {
	return s.requestWriter.Write(p)
}

func (s *httpStream) Read(p []byte) (int, error) {
	if err := s.waitResponse(); err != nil {
		return 0, err
	}
	return s.resp.Body.Read(p)
}

func (s *httpStream) Close() error {
	_ = s.requestWriter.Close()
	if err := s.waitResponse(); err == nil && s.resp != nil {
		_ = s.resp.Body.Close()
	}
	if s.closeIdle != nil {
		s.closeIdle()
	}
	return nil
}

func (s *httpStream) waitResponse() error {
	s.once.Do(func() {
		select {
		case resp := <-s.responseCh:
			s.resp = resp
		case err := <-s.errorCh:
			s.err = err
		}
	})
	return s.err
}
