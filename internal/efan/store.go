package efan

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Service struct {
	ServiceID      string `json:"service_id,omitempty"`
	Name           string `json:"name,omitempty"`
	SubscribeToken string `json:"subscribe_token,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	Traffic        string `json:"traffic,omitempty"`
}

type Session struct {
	Email        string    `json:"email"`
	AccessToken  string    `json:"access_token"`
	SessionToken string    `json:"session_token"`
	Cookie       string    `json:"cookie,omitempty"`
	ExpiresAt    int64     `json:"expires_at,omitempty"`
	Services     []Service `json:"services,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (s Session) Expired() bool {
	if s.ExpiresAt <= 0 {
		return false
	}
	return time.Now().Unix() >= s.ExpiresAt
}

type Settings struct {
	SelectedNode string `json:"selected_node,omitempty"`
	Listen       string `json:"listen,omitempty"`
	HTTPListen   string `json:"http_listen,omitempty"`
	SystemProxy  bool   `json:"system_proxy,omitempty"`
	Did          string `json:"did,omitempty"`
	Fit          int64  `json:"fit,omitempty"`
	AppVersion   string `json:"app_version,omitempty"`
}

func LoadSession(path string) (Session, error) {
	var s Session
	if err := readJSON(path, &s); err != nil {
		return Session{}, err
	}
	if s.AccessToken == "" && s.SessionToken == "" {
		return Session{}, errors.New("session file contains no token")
	}
	return s, nil
}

func SaveSession(path string, s Session) error {
	s.UpdatedAt = time.Now()
	return writeJSON(path, s)
}

func ClearSession(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func LoadSettings(path string) (Settings, error) {
	var s Settings
	if err := readJSON(path, &s); err != nil {
		if os.IsNotExist(err) {
			return Settings{}, nil
		}
		return Settings{}, err
	}
	return s, nil
}

func SaveSettings(path string, s Settings) error {
	return writeJSON(path, s)
}

func EnsureDID(settings *Settings) (string, error) {
	if settings.Did != "" {
		// The Windows client stores the DID as 32 hex characters. Accept a
		// hyphenated UUID too so an ID copied from elsewhere still works.
		settings.Did = normalizeDID(settings.Did)
		return settings.Did, nil
	}
	did, err := NewDID()
	if err != nil {
		return "", err
	}
	settings.Did = did
	if settings.Fit == 0 {
		settings.Fit = time.Now().UnixMilli()
	}
	return did, nil
}

// NewDID returns the 32-hex-character device id shape used by the official
// client (the app hashes the machine id to 16 bytes and drops the UUID dashes).
func NewDID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func normalizeDID(did string) string {
	did = strings.TrimSpace(did)
	if len(did) == 36 && did[8] == '-' && did[13] == '-' && did[18] == '-' && did[23] == '-' {
		return strings.ReplaceAll(did, "-", "")
	}
	return did
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFile0600(path, data)
}

func writeFile0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
