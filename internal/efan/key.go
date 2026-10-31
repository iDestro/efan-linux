package efan

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The Windows client embeds an RSA-2048 private key as a PEM blob XORed with
// the repeating byte string "encoding". The same key is used to decrypt the
// account's proxy configuration and to sign DeviceInfo headers with its
// public half.
var keyXOR = []byte("encoding")

// ExtractKeyFromDLL reads client.dll and returns the embedded PEM private key.
// It scans for the XOR-obfuscated PEM header, so it is not tied to one exact
// build offset.
func ExtractKeyFromDLL(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ExtractKeyFromBytes(data)
}

func ExtractKeyFromBytes(data []byte) ([]byte, error) {
	headers := [][]byte{
		[]byte("-----BEGIN RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN PRIVATE KEY-----"),
	}
	for _, header := range headers {
		pattern := xorBytes(header, keyXOR)
		searchFrom := 0
		for {
			idx := bytes.Index(data[searchFrom:], pattern)
			if idx < 0 {
				break
			}
			start := searchFrom + idx
			end := start + 8192
			if end > len(data) {
				end = len(data)
			}
			decoded := xorBytes(data[start:end], keyXOR)
			for _, footer := range [][]byte{
				[]byte("-----END RSA PRIVATE KEY-----"),
				[]byte("-----END PRIVATE KEY-----"),
			} {
				fi := bytes.Index(decoded, footer)
				if fi < 0 {
					continue
				}
				pemBytes := append([]byte(nil), decoded[:fi+len(footer)]...)
				pemBytes = append(pemBytes, '\n')
				if _, err := ParsePrivateKeyPEM(pemBytes); err == nil {
					return pemBytes, nil
				}
			}
			searchFrom = start + 1
		}
	}
	return nil, errors.New("embedded RSA private key not found in client.dll")
}

func xorBytes(in, key []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func ParsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("embedded key is %T, want RSA", key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
	}
}

func LoadKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(data)
}

func SaveKey(path string, pemBytes []byte) error {
	if _, err := ParsePrivateKeyPEM(pemBytes); err != nil {
		return fmt.Errorf("refusing to save invalid key: %w", err)
	}
	return writeFile0600(path, pemBytes)
}

func KeyFingerprint(key *rsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:8])
}

// FindClientDLL looks in the places a local Efan extraction is likely to live.
func FindClientDLL(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("EFAN_CLIENT_DLL"); env != "" {
		return env
	}
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, "Downloads", "efan-extract", "client.dll"),
			filepath.Join(home, "Downloads", "efanapp", "client.dll"),
		)
	}
	for _, candidate := range candidates {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate
		}
	}
	return ""
}

func EnsureKey(paths Paths, explicitDLL string) (*rsa.PrivateKey, error) {
	if key, err := LoadKey(paths.Key); err == nil {
		return key, nil
	}
	dll := FindClientDLL(explicitDLL)
	if dll == "" {
		return nil, fmt.Errorf("no RSA key at %s and no client.dll found; run: efan extract-key --dll /path/to/client.dll", paths.Key)
	}
	pemBytes, err := ExtractKeyFromDLL(dll)
	if err != nil {
		return nil, err
	}
	if err := SaveKey(paths.Key, pemBytes); err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(pemBytes)
}
