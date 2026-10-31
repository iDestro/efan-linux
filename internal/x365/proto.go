package x365

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const (
	multipathControlHost = "multipath.internal"
	multipathControlPort = 1

	frameHello = 0
	frameData  = 1
	frameClose = 3
	frameACK   = 5
)

type frame struct {
	Type     byte
	Seq      uint64
	Reserved byte
	Payload  []byte
}

func MaterialFromUUID(uuidText string) ([]byte, error) {
	cleaned := strings.ReplaceAll(uuidText, "-", "")
	raw, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, err
	}
	if len(raw) != 16 {
		return nil, fmt.Errorf("uuid material must be 16 bytes, got %d", len(raw))
	}
	return raw, nil
}

func buildRequest(destHost string, destPort int, material []byte) ([]byte, error) {
	if len(material) != 16 {
		return nil, fmt.Errorf("x365 material must be exactly 16 bytes, got %d", len(material))
	}
	if destPort < 0 || destPort > 65535 {
		return nil, fmt.Errorf("destination port out of range: %d", destPort)
	}
	frame := make([]byte, 0, 64+len(destHost))
	frame = append(frame, 'X', '3', '6', '5', 1, 1)
	frame = append(frame, material...)
	frame = append(frame, byte(destPort>>8), byte(destPort))

	if ip := net.ParseIP(destHost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			frame = append(frame, 1)
			frame = append(frame, v4...)
			return frame, nil
		}
		v6 := ip.To16()
		if v6 == nil {
			return nil, fmt.Errorf("invalid IP address: %s", destHost)
		}
		frame = append(frame, 3)
		frame = append(frame, v6...)
		return frame, nil
	}

	hostBytes := []byte(destHost)
	if len(hostBytes) > 255 {
		return nil, fmt.Errorf("domain name too long: %d", len(hostBytes))
	}
	frame = append(frame, 2, byte(len(hostBytes)))
	frame = append(frame, hostBytes...)
	return frame, nil
}

func buildFrame(frameType byte, seq uint64, payload []byte) ([]byte, error) {
	if len(payload) > 0xffffff {
		return nil, fmt.Errorf("multipath payload too large: %d", len(payload))
	}
	frame := make([]byte, 13+len(payload))
	writeFrameHeader(frame[:13], frameType, seq, len(payload))
	copy(frame[13:], payload)
	return frame, nil
}

func writeFrameHeader(dst []byte, frameType byte, seq uint64, payloadLen int) {
	dst[0] = frameType
	for i := 0; i < 8; i++ {
		dst[1+i] = byte(seq >> (56 - i*8))
	}
	dst[9] = 0
	dst[10] = byte(payloadLen >> 16)
	dst[11] = byte(payloadLen >> 8)
	dst[12] = byte(payloadLen)
}

func parseFrame(buf []byte) (frame, int, error) {
	if len(buf) < 13 {
		return frame{}, 0, fmt.Errorf("need more data")
	}
	payloadLen := int(buf[10])<<16 | int(buf[11])<<8 | int(buf[12])
	total := 13 + payloadLen
	if len(buf) < total {
		return frame{}, 0, fmt.Errorf("need more data")
	}
	var seq uint64
	for i := 0; i < 8; i++ {
		seq = (seq << 8) | uint64(buf[1+i])
	}
	payload := make([]byte, payloadLen)
	copy(payload, buf[13:total])
	return frame{Type: buf[0], Seq: seq, Reserved: buf[9], Payload: payload}, total, nil
}

func buildHello(host string, port int, streamID [16]byte) ([]byte, error) {
	if host == "" {
		return nil, fmt.Errorf("hello host is required")
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("hello port out of range: %d", port)
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("hello host too long: %d", len(host))
	}
	payload := make([]byte, 0, 21+len(host))
	payload = append(payload, streamID[:]...)
	payload = append(payload, 0, 1)
	payload = append(payload, byte(port>>8), byte(port), byte(len(host)))
	payload = append(payload, []byte(host)...)
	return payload, nil
}

type streamFramer struct {
	StreamID [16]byte
	WriteSeq uint64
}

func newStreamFramer() (*streamFramer, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return &streamFramer{StreamID: id}, nil
}

func (f *streamFramer) openFrame(host string, port int) ([]byte, error) {
	hello, err := buildHello(host, port, f.StreamID)
	if err != nil {
		return nil, err
	}
	return buildFrame(frameHello, 0, hello)
}

func (f *streamFramer) dataFrame(payload []byte) ([]byte, error) {
	frame, err := buildFrame(frameData, f.WriteSeq, payload)
	if err != nil {
		return nil, err
	}
	f.WriteSeq += uint64(len(payload))
	return frame, nil
}

func (f *streamFramer) ackFrame(seq uint64) ([]byte, error) {
	return buildFrame(frameACK, seq, nil)
}

func (f *streamFramer) closeFrame() ([]byte, error) {
	return buildFrame(frameClose, f.WriteSeq, nil)
}
