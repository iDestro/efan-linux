package x365

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	shadowsocksAEADTagSize     = 16
	shadowsocksAEADNonceSize   = 12
	shadowsocksMaxChunkPayload = 0x3fff
	shadowsocks2022FixedHeader = 11
	shadowsocks2022Context     = "shadowsocks 2022 session subkey"
)

type shadowsocksSniffState int

const (
	shadowsocksSniffNeedMore shadowsocksSniffState = iota
	shadowsocksSniffFound
	shadowsocksSniffFailed
)

type shadowsocksTargetSniffer struct {
	config     shadowsocksSniffConfig
	spec       shadowsocksCipher
	limit      int
	masterKey  []byte
	candidates []shadowsocks2022KeyCandidate
	buffer     []byte
	done       bool
}

func newShadowsocksTargetSniffer(configs []shadowsocksSniffConfig, host string, port int) *shadowsocksTargetSniffer {
	config, ok := matchingShadowsocksSniffConfig(configs, host, port)
	if !ok {
		return nil
	}
	spec, ok := shadowsocksCipherSpec(config.Method)
	if !ok {
		return nil
	}
	sniffer := &shadowsocksTargetSniffer{
		config: config,
		spec:   spec,
		limit:  shadowsocksSniffBufferLimitForSpec(config, spec),
	}
	if sniffer.limit <= 0 {
		return nil
	}
	if spec.AEAD2022 {
		sniffer.candidates = shadowsocks2022KeyCandidates(config.Password, spec.KeySize)
		if len(sniffer.candidates) == 0 {
			return nil
		}
	} else {
		sniffer.masterKey = evpBytesToKey([]byte(config.Password), spec.KeySize)
	}
	return sniffer
}

func matchingShadowsocksSniffConfig(configs []shadowsocksSniffConfig, host string, port int) (shadowsocksSniffConfig, bool) {
	for _, config := range configs {
		if config.Port != port {
			continue
		}
		if sameHost(config.Server, host) {
			return config, true
		}
	}
	return shadowsocksSniffConfig{}, false
}

func sameHost(left, right string) bool {
	leftIP := net.ParseIP(left)
	rightIP := net.ParseIP(right)
	if leftIP != nil || rightIP != nil {
		return leftIP != nil && rightIP != nil && leftIP.Equal(rightIP)
	}
	return strings.EqualFold(left, right)
}

func (s *shadowsocksTargetSniffer) Observe(p []byte) (string, bool) {
	if s == nil || s.done || len(p) == 0 {
		return "", false
	}
	limit := s.limit
	if limit <= 0 {
		s.done = true
		return "", false
	}
	if len(s.buffer) < limit {
		remaining := limit - len(s.buffer)
		if len(p) > remaining {
			p = p[:remaining]
		}
		s.buffer = append(s.buffer, p...)
	}
	target, state := s.sniff(s.buffer)
	switch state {
	case shadowsocksSniffFound:
		s.done = true
		return target, true
	case shadowsocksSniffFailed:
		s.done = true
	case shadowsocksSniffNeedMore:
		if len(s.buffer) >= limit {
			s.done = true
		}
	}
	return "", false
}

func shadowsocksSniffBufferLimit(method string) int {
	return shadowsocksSniffBufferLimitForConfig(shadowsocksSniffConfig{Method: method})
}

func shadowsocksSniffBufferLimitForConfig(config shadowsocksSniffConfig) int {
	method := config.Method
	spec, ok := shadowsocksCipherSpec(method)
	if !ok {
		return 0
	}
	return shadowsocksSniffBufferLimitForSpec(config, spec)
}

func shadowsocksSniffBufferLimitForSpec(config shadowsocksSniffConfig, spec shadowsocksCipher) int {
	if spec.AEAD2022 {
		return spec.SaltSize + shadowsocks2022EIHLen(config.Password) + shadowsocks2022FixedHeader + shadowsocksAEADTagSize + 0xffff + shadowsocksAEADTagSize
	}
	return spec.SaltSize + 2 + shadowsocksAEADTagSize + shadowsocksMaxChunkPayload + shadowsocksAEADTagSize
}

func (s *shadowsocksTargetSniffer) sniff(data []byte) (string, shadowsocksSniffState) {
	if s.spec.AEAD2022 {
		return sniffShadowsocks2022TargetWithCandidates(s.candidates, s.spec, data)
	}
	return sniffShadowsocksTargetWithMasterKey(s.spec, s.masterKey, data)
}

func sniffShadowsocksTarget(config shadowsocksSniffConfig, data []byte) (string, shadowsocksSniffState) {
	spec, ok := shadowsocksCipherSpec(config.Method)
	if !ok {
		return "", shadowsocksSniffFailed
	}
	if spec.AEAD2022 {
		return sniffShadowsocks2022Target(config, spec, data)
	}
	masterKey := evpBytesToKey([]byte(config.Password), spec.KeySize)
	return sniffShadowsocksTargetWithMasterKey(spec, masterKey, data)
}

func sniffShadowsocksTargetWithMasterKey(spec shadowsocksCipher, masterKey []byte, data []byte) (string, shadowsocksSniffState) {
	if len(data) < spec.SaltSize+2+shadowsocksAEADTagSize {
		return "", shadowsocksSniffNeedMore
	}

	salt := data[:spec.SaltSize]
	subkey, err := deriveShadowsocksSubkeyFromMasterKey(masterKey, salt, spec.KeySize)
	if err != nil {
		return "", shadowsocksSniffFailed
	}
	aead, err := spec.NewAEAD(subkey)
	if err != nil {
		return "", shadowsocksSniffFailed
	}

	nonce := make([]byte, shadowsocksAEADNonceSize)
	lengthStart := spec.SaltSize
	lengthEnd := lengthStart + 2 + shadowsocksAEADTagSize
	lengthPlaintext, err := aead.Open(nil, nonce, data[lengthStart:lengthEnd], nil)
	if err != nil {
		return "", shadowsocksSniffFailed
	}
	if len(lengthPlaintext) != 2 {
		return "", shadowsocksSniffFailed
	}
	payloadLen := int(binary.BigEndian.Uint16(lengthPlaintext))
	if payloadLen <= 0 || payloadLen > shadowsocksMaxChunkPayload {
		return "", shadowsocksSniffFailed
	}

	payloadStart := lengthEnd
	payloadEnd := payloadStart + payloadLen + shadowsocksAEADTagSize
	if len(data) < payloadEnd {
		return "", shadowsocksSniffNeedMore
	}
	incrementShadowsocksNonce(nonce)
	payload, err := aead.Open(nil, nonce, data[payloadStart:payloadEnd], nil)
	if err != nil {
		return "", shadowsocksSniffFailed
	}
	target, ok := parseShadowsocksTargetAddress(payload)
	if !ok {
		return "", shadowsocksSniffFailed
	}
	return target, shadowsocksSniffFound
}

type shadowsocksCipher struct {
	KeySize  int
	SaltSize int
	NewAEAD  func([]byte) (cipher.AEAD, error)
	AEAD2022 bool
}

func shadowsocksCipherSpec(method string) (shadowsocksCipher, bool) {
	switch strings.ToLower(strings.TrimSpace(method)) {
	case "aes-128-gcm":
		return shadowsocksCipher{KeySize: 16, SaltSize: 16, NewAEAD: newAESGCM}, true
	case "aes-256-gcm":
		return shadowsocksCipher{KeySize: 32, SaltSize: 32, NewAEAD: newAESGCM}, true
	case "chacha20-ietf-poly1305":
		return shadowsocksCipher{KeySize: 32, SaltSize: 32, NewAEAD: chacha20poly1305.New}, true
	case "2022-blake3-aes-128-gcm":
		return shadowsocksCipher{KeySize: 16, SaltSize: 16, NewAEAD: newAESGCM, AEAD2022: true}, true
	case "2022-blake3-aes-256-gcm":
		return shadowsocksCipher{KeySize: 32, SaltSize: 32, NewAEAD: newAESGCM, AEAD2022: true}, true
	default:
		return shadowsocksCipher{}, false
	}
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sniffShadowsocks2022Target(config shadowsocksSniffConfig, spec shadowsocksCipher, data []byte) (string, shadowsocksSniffState) {
	candidates := shadowsocks2022KeyCandidates(config.Password, spec.KeySize)
	if len(candidates) == 0 {
		return "", shadowsocksSniffFailed
	}
	return sniffShadowsocks2022TargetWithCandidates(candidates, spec, data)
}

func sniffShadowsocks2022TargetWithCandidates(candidates []shadowsocks2022KeyCandidate, spec shadowsocksCipher, data []byte) (string, shadowsocksSniffState) {
	needMore := false
	for _, candidate := range candidates {
		target, state := sniffShadowsocks2022TargetWithKey(candidate, spec, data)
		switch state {
		case shadowsocksSniffFound:
			return target, state
		case shadowsocksSniffNeedMore:
			needMore = true
		}
	}
	if needMore {
		return "", shadowsocksSniffNeedMore
	}
	return "", shadowsocksSniffFailed
}

type shadowsocks2022KeyCandidate struct {
	key    []byte
	eihLen int
}

func sniffShadowsocks2022TargetWithKey(candidate shadowsocks2022KeyCandidate, spec shadowsocksCipher, data []byte) (string, shadowsocksSniffState) {
	fixedStart := spec.SaltSize + candidate.eihLen
	fixedEnd := fixedStart + shadowsocks2022FixedHeader + shadowsocksAEADTagSize
	if len(data) < fixedEnd {
		return "", shadowsocksSniffNeedMore
	}

	salt := data[:spec.SaltSize]
	subkey := deriveShadowsocks2022Subkey(candidate.key, salt, spec.KeySize)
	aead, err := spec.NewAEAD(subkey)
	if err != nil {
		return "", shadowsocksSniffFailed
	}

	nonce := make([]byte, shadowsocksAEADNonceSize)
	fixedHeader, err := aead.Open(nil, nonce, data[fixedStart:fixedEnd], nil)
	if err != nil {
		return "", shadowsocksSniffFailed
	}
	if len(fixedHeader) != shadowsocks2022FixedHeader || fixedHeader[0] != 0 {
		return "", shadowsocksSniffFailed
	}
	variableLen := int(binary.BigEndian.Uint16(fixedHeader[9:11]))
	if variableLen <= 0 {
		return "", shadowsocksSniffFailed
	}

	variableStart := fixedEnd
	variableEnd := variableStart + variableLen + shadowsocksAEADTagSize
	if len(data) < variableEnd {
		return "", shadowsocksSniffNeedMore
	}
	incrementShadowsocksNonce(nonce)
	variableHeader, err := aead.Open(nil, nonce, data[variableStart:variableEnd], nil)
	if err != nil {
		return "", shadowsocksSniffFailed
	}
	target, ok := parseShadowsocksTargetAddress(variableHeader)
	if !ok {
		return "", shadowsocksSniffFailed
	}
	return target, shadowsocksSniffFound
}

func deriveShadowsocks2022Subkey(key []byte, salt []byte, keySize int) []byte {
	keyMaterial := make([]byte, 0, len(key)+len(salt))
	keyMaterial = append(keyMaterial, key...)
	keyMaterial = append(keyMaterial, salt...)
	subkey := make([]byte, 32)
	blake3.DeriveKey(shadowsocks2022Context, keyMaterial, subkey)
	return subkey[:keySize]
}

func shadowsocks2022KeyCandidates(password string, keySize int) []shadowsocks2022KeyCandidate {
	parts := strings.Split(password, ":")
	if len(parts) > 1 {
		key, ok := decodeShadowsocks2022PSK(parts[len(parts)-1], keySize)
		if !ok {
			return nil
		}
		return []shadowsocks2022KeyCandidate{{key: key, eihLen: 16 * (len(parts) - 1)}}
	}
	key, ok := decodeShadowsocks2022PSK(password, keySize)
	if !ok {
		return nil
	}
	return []shadowsocks2022KeyCandidate{{key: key}}
}

func shadowsocks2022EIHLen(password string) int {
	if strings.Count(password, ":") == 0 {
		return 0
	}
	return 16 * strings.Count(password, ":")
}

func decodeShadowsocks2022PSK(password string, keySize int) ([]byte, bool) {
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		key, err := encoding.DecodeString(password)
		if err == nil && len(key) == keySize {
			return key, true
		}
	}
	if len(password) == keySize {
		return []byte(password), true
	}
	return nil, false
}

func deriveShadowsocksSubkey(password string, salt []byte, keySize int) ([]byte, error) {
	masterKey := evpBytesToKey([]byte(password), keySize)
	return deriveShadowsocksSubkeyFromMasterKey(masterKey, salt, keySize)
}

func deriveShadowsocksSubkeyFromMasterKey(masterKey []byte, salt []byte, keySize int) ([]byte, error) {
	reader := hkdf.New(sha1.New, masterKey, salt, []byte("ss-subkey"))
	subkey := make([]byte, keySize)
	if _, err := io.ReadFull(reader, subkey); err != nil {
		return nil, err
	}
	return subkey, nil
}

func evpBytesToKey(password []byte, keySize int) []byte {
	var key []byte
	var previous []byte
	for len(key) < keySize {
		digest := md5.New()
		_, _ = digest.Write(previous)
		_, _ = digest.Write(password)
		previous = digest.Sum(nil)
		key = append(key, previous...)
	}
	return key[:keySize]
}

func incrementShadowsocksNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func parseShadowsocksTargetAddress(payload []byte) (string, bool) {
	if len(payload) < 1 {
		return "", false
	}
	var host string
	var portOffset int
	switch payload[0] {
	case 1:
		if len(payload) < 1+net.IPv4len+2 {
			return "", false
		}
		host = net.IP(payload[1 : 1+net.IPv4len]).String()
		portOffset = 1 + net.IPv4len
	case 3:
		if len(payload) < 2 {
			return "", false
		}
		hostLen := int(payload[1])
		if hostLen == 0 || len(payload) < 2+hostLen+2 {
			return "", false
		}
		host = string(payload[2 : 2+hostLen])
		portOffset = 2 + hostLen
	case 4:
		if len(payload) < 1+net.IPv6len+2 {
			return "", false
		}
		host = net.IP(payload[1 : 1+net.IPv6len]).String()
		portOffset = 1 + net.IPv6len
	default:
		return "", false
	}
	port := binary.BigEndian.Uint16(payload[portOffset : portOffset+2])
	if host == "" || port == 0 {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), true
}

func formatTargetChain(outer, inner string) string {
	if inner == "" || inner == outer {
		return outer
	}
	return fmt.Sprintf("%s->%s", outer, inner)
}
