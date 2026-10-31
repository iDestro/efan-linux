package efan

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"efan-linux/internal/x365"
)

func TestExtractKeyFromBytes(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	data := append([]byte("some unrelated leading bytes"), xorBytes(pemBytes, keyXOR)...)
	data = append(data, []byte("trailing bytes")...)
	got, err := ExtractKeyFromBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePrivateKeyPEM(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.N.Cmp(key.N) != 0 {
		t.Fatal("extracted key does not match")
	}
}

func TestDecryptProxyRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("proxies:\n  香港01:\n    - x365://00112233-4455-6677-8899-aabbccddeeff@example.com:443?path=/x\n")
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	const chunkSize = 200
	var ciphertext []byte
	for offset := 0; offset < compressed.Len(); offset += chunkSize {
		end := offset + chunkSize
		if end > compressed.Len() {
			end = compressed.Len()
		}
		block, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, compressed.Bytes()[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		ciphertext = append(ciphertext, block...)
	}
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	got, err := DecryptProxy(encoded, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypted payload mismatch:\n%s", got)
	}
}

func TestNormalizeProxyConfig(t *testing.T) {
	uuid := "00112233-4455-6677-8899-aabbccddeeff"
	input := "香港01:\n  - x365://" + uuid + "@example.com:443?path=/x&host=example.com&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&sid=0123456789abcdef\n"
	out, err := NormalizeProxyConfig([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "proxies:") {
		t.Fatalf("normalized config is missing proxies: %s", out)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := x365.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(cfg.Nodes))
	}
	if cfg.Nodes[0].UserID != uuid {
		t.Fatalf("got UUID %q, want %q", cfg.Nodes[0].UserID, uuid)
	}
}

func TestDeviceInfoSignRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	info := DeviceInfo{
		AppName:    "efanapp",
		OS:         "win32",
		AppVersion: "1.0.68",
		OSArch:     "amd64",
		Did:        "00112233-4455-6677-8899-aabbccddeeff",
	}
	signature, err := info.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	for offset := 0; offset < len(raw); offset += key.Size() {
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, key, raw[offset:offset+key.Size()])
		if err != nil {
			t.Fatal(err)
		}
		payload = append(payload, chunk...)
	}
	var got DeviceInfo
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Did != info.Did || got.AppName != info.AppName || got.AppVersion != info.AppVersion {
		t.Fatalf("signature payload mismatch: %+v", got)
	}
}

func TestDaemonStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "daemon.json")
	pidPath := filepath.Join(dir, "efan.pid")
	state := DaemonState{
		PID:         4321,
		Node:        "香港01",
		Socks:       "127.0.0.1:10865",
		HTTP:        "127.0.0.1:10866",
		SystemProxy: true,
		Debug:       true,
	}
	if err := SaveDaemonState(statePath, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDaemonState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PID != state.PID || loaded.Node != state.Node || loaded.Socks != state.Socks ||
		loaded.HTTP != state.HTTP || loaded.SystemProxy != state.SystemProxy || loaded.Debug != state.Debug {
		t.Fatalf("loaded state mismatch: %+v", loaded)
	}
	if loaded.StartedAt.IsZero() {
		t.Fatal("StartedAt was not filled in")
	}
	if err := SavePID(pidPath, state.PID); err != nil {
		t.Fatal(err)
	}
	pid, err := LoadPID(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	if pid != state.PID {
		t.Fatalf("got pid %d, want %d", pid, state.PID)
	}
	if err := RemoveDaemonState(statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("daemon state still exists: %v", err)
	}
}

func TestPrintProxyEnv(t *testing.T) {
	var b bytes.Buffer
	PrintProxyEnv(&b, 10866, 10865)
	text := b.String()
	for _, want := range []string{
		"http://127.0.0.1:10866",
		"socks5h://127.0.0.1:10865",
		"no_proxy=localhost,127.0.0.1,::1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("proxy env missing %q:\n%s", want, text)
		}
	}
	b.Reset()
	PrintProxyUnset(&b)
	if !strings.Contains(b.String(), "unset http_proxy") {
		t.Fatalf("unset output missing http_proxy: %s", b.String())
	}
}
