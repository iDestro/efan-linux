package efan

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

var ErrNoProxy = errors.New("app data contains no proxy field")

// DecryptProxy reverses comm.DecryptConfigData: base64 -> RSA PKCS#1 v1.5
// blocks -> concatenate -> zlib -> YAML/JSON text.
func DecryptProxy(encoded string, key *rsa.PrivateKey) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, ErrNoProxy
	}
	raw, err := decodeBase64Flexible(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode proxy base64: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("proxy ciphertext is empty")
	}

	blockSize := key.Size()
	if blockSize <= 0 {
		return nil, errors.New("invalid RSA key")
	}
	if len(raw)%blockSize != 0 {
		// Some captures include a small JSON wrapper or use hex. Try hex once.
		if hexDecoded, hexErr := hex.DecodeString(encoded); hexErr == nil && len(hexDecoded)%blockSize == 0 {
			raw = hexDecoded
		} else {
			return nil, fmt.Errorf("proxy ciphertext length %d is not a multiple of RSA block size %d", len(raw), blockSize)
		}
	}

	var compressed []byte
	for offset := 0; offset < len(raw); offset += blockSize {
		block := raw[offset : offset+blockSize]
		chunk, err := key.Decrypt(rand.Reader, block, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA decrypt block %d: %w", offset/blockSize, err)
		}
		compressed = append(compressed, chunk...)
	}

	plain, err := decompress(compressed)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(plain)) == 0 {
		return nil, errors.New("decrypted proxy data is empty")
	}
	return plain, nil
}

func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		default:
			return r
		}
	}, s)
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(s); err == nil {
			return decoded, nil
		} else {
			lastErr = err
		}
	}
	return nil, lastErr
}

func decompress(data []byte) ([]byte, error) {
	// zlib is what the official client uses.
	if out, err := readAll(zlib.NewReader(bytes.NewReader(data))); err == nil {
		return out, nil
	}
	if out, err := readAll(gzip.NewReader(bytes.NewReader(data))); err == nil {
		return out, nil
	}
	newFlate := flate.NewReader(bytes.NewReader(data))
	if out, err := io.ReadAll(newFlate); err == nil {
		_ = newFlate.Close()
		return out, nil
	}
	_ = newFlate.Close()
	// Older captures were sometimes stored without compression. Accept text
	// that already looks like a proxy file.
	if utf8.Valid(data) {
		text := string(data)
		if strings.Contains(text, "x365://") || strings.Contains(text, "proxies:") || strings.Contains(text, `"proxies"`) {
			return data, nil
		}
	}
	return nil, fmt.Errorf("decrypted data is not zlib/gzip/deflate or proxy text (first bytes %s)", hexPreview(data, 32))
}

func readAll(r io.ReadCloser, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func hexPreview(data []byte, n int) string {
	if len(data) > n {
		data = data[:n]
	}
	return hex.EncodeToString(data)
}
