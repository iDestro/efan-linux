package x365

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

func openX365Multipath(ctx context.Context, cfg ServerConfig, destHost string, destPort int) (io.ReadWriteCloser, error) {
	stream, err := openStream(ctx, cfg.Node, cfg.Timeout)
	if err != nil {
		return nil, err
	}
	return openMultipath(stream, cfg.Material, destHost, destPort)
}

func openMultipath(stream io.ReadWriteCloser, material []byte, destHost string, destPort int) (io.ReadWriteCloser, error) {
	req, err := buildRequest(multipathControlHost, multipathControlPort, material)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if _, err := stream.Write(req); err != nil {
		_ = stream.Close()
		return nil, err
	}
	resp := make([]byte, 5)
	if _, err := io.ReadFull(stream, resp); err != nil {
		_ = stream.Close()
		return nil, err
	}
	if string(resp[:4]) != "X365" || resp[4] != 0 {
		_ = stream.Close()
		return nil, fmt.Errorf("bad X365 response: %x", resp)
	}
	framer, err := newStreamFramer()
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	openFrame, err := framer.openFrame(destHost, destPort)
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	if _, err := stream.Write(openFrame); err != nil {
		_ = stream.Close()
		return nil, err
	}
	return &multipathConn{raw: stream, framer: framer}, nil
}

type multipathConn struct {
	raw    io.ReadWriteCloser
	framer *streamFramer
	buf    []byte
}

func (c *multipathConn) Read(p []byte) (int, error) {
	for len(c.buf) == 0 {
		frame, err := readFrame(c.raw)
		if err != nil {
			return 0, err
		}
		switch frame.Type {
		case frameData:
			ack, err := c.framer.ackFrame(frame.Seq + uint64(len(frame.Payload)))
			if err == nil {
				_, _ = c.raw.Write(ack)
			}
			c.buf = frame.Payload
		case frameClose:
			return 0, io.EOF
		case frameACK, frameHello:
			continue
		default:
			continue
		}
	}
	n := copy(p, c.buf)
	if n == len(c.buf) {
		c.buf = nil
	} else {
		c.buf = c.buf[n:]
	}
	return n, nil
}

func (c *multipathConn) Write(p []byte) (int, error) {
	if len(p) > 0xffffff {
		return 0, fmt.Errorf("multipath payload too large: %d", len(p))
	}
	var header [13]byte
	writeFrameHeader(header[:], frameData, c.framer.WriteSeq, len(p))
	if err := writeFull(c.raw, header[:]); err != nil {
		return 0, err
	}
	if err := writeFull(c.raw, p); err != nil {
		return 0, err
	}
	c.framer.WriteSeq += uint64(len(p))
	return len(p), nil
}

func (c *multipathConn) Close() error {
	if frame, err := c.framer.closeFrame(); err == nil {
		_, _ = c.raw.Write(frame)
	}
	return c.raw.Close()
}

func readFrame(r io.Reader) (frame, error) {
	var header [13]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return frame{}, err
	}
	payloadLen := int(header[10])<<16 | int(header[11])<<8 | int(header[12])
	var seq uint64
	for i := 0; i < 8; i++ {
		seq = (seq << 8) | uint64(header[1+i])
	}
	result := frame{Type: header[0], Seq: seq, Reserved: header[9]}
	if payloadLen > 0 {
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return frame{}, err
		}
		result.Payload = payload
	}
	return result, nil
}

type relayStats struct {
	Upload   int64
	Download int64
}

type relayResult struct {
	direction string
	n         int64
	err       error
}

func relayMultipath(client net.Conn, upstream io.ReadWriteCloser, liveStats *ConnectionStats, observeUpload func([]byte)) (relayStats, error) {
	resultCh := make(chan relayResult, 2)
	go func() {
		n, err := copyWithPooledBuffer(countingWriter{writer: uploadObserver{writer: upstream, observe: observeUpload}, add: liveStats.AddUpload}, client)
		resultCh <- relayResult{direction: "upload", n: n, err: err}
	}()
	go func() {
		n, err := copyWithPooledBuffer(countingWriter{writer: client, add: liveStats.AddDownload}, upstream)
		resultCh <- relayResult{direction: "download", n: n, err: err}
	}()
	first := <-resultCh
	_ = upstream.Close()
	_ = client.Close()
	second := <-resultCh

	var stats relayStats
	for _, result := range []relayResult{first, second} {
		switch result.direction {
		case "upload":
			stats.Upload = result.n
		case "download":
			stats.Download = result.n
		}
		if result.err != nil && !isBenignClientError(result.err) {
			return stats, result.err
		}
	}
	return stats, nil
}

const relayBufferSize = 32 * 1024

var relayBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, relayBufferSize)
		return &buf
	},
}

func copyWithPooledBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := relayBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer relayBufferPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, buf)
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type uploadObserver struct {
	writer  io.Writer
	observe func([]byte)
}

func (w uploadObserver) Write(p []byte) (int, error) {
	if w.observe != nil && len(p) > 0 {
		w.observe(p)
	}
	return w.writer.Write(p)
}

type countingWriter struct {
	writer io.Writer
	add    func(int64)
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 && w.add != nil {
		w.add(int64(n))
	}
	return n, err
}
