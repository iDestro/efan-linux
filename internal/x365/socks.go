package x365

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

func socksHandshake(reader *bufio.Reader, writer io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("read SOCKS5 greeting: %w", err)
	}
	if header[0] != 5 {
		return errors.New("not a SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return fmt.Errorf("read SOCKS5 methods: %w", err)
	}
	if !bytes.Contains(methods, []byte{0}) {
		_, _ = writer.Write([]byte{5, 0xff})
		return errors.New("SOCKS5 no-auth method is not offered")
	}
	_, err := writer.Write([]byte{5, 0})
	return err
}

func socksReadConnect(reader *bufio.Reader, writer io.Writer) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", 0, fmt.Errorf("read SOCKS5 request header: %w", err)
	}
	if header[0] != 5 {
		return "", 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	cmd := header[1]
	if cmd != 1 {
		_ = writeSocksReply(writer, 7)
		return "", 0, fmt.Errorf("unsupported SOCKS5 command: %s", socksCommandName(cmd))
	}
	var host string
	switch header[3] {
	case 1:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 IPv4 address: %w", err)
		}
		host = net.IP(addr).String()
	case 3:
		sizeByte, err := reader.ReadByte()
		if err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 domain length: %w", err)
		}
		addr := make([]byte, int(sizeByte))
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 domain: %w", err)
		}
		host = string(addr)
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", 0, fmt.Errorf("read SOCKS5 IPv6 address: %w", err)
		}
		host = net.IP(addr).String()
	default:
		_ = writeSocksReply(writer, 8)
		return "", 0, fmt.Errorf("unsupported SOCKS5 address type: %d", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", 0, fmt.Errorf("read SOCKS5 port: %w", err)
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	return host, port, nil
}

func isFakeIPHost(host string) bool {
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return false
	}
	return ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)
}

func writeSocksReply(writer io.Writer, code byte) error {
	_, err := writer.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func socksCommandName(cmd byte) string {
	switch cmd {
	case 1:
		return "CONNECT(1)"
	case 2:
		return "BIND(2)"
	case 3:
		return "UDP_ASSOCIATE(3)"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", cmd)
	}
}
