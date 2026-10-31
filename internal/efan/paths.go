package efan

import (
	"os"
	"path/filepath"
)

// Paths holds the local, per-user state for the native client. Everything is
// kept under $XDG_CONFIG_HOME/efan (normally ~/.config/efan).
type Paths struct {
	Dir         string
	Key         string
	Session     string
	Config      string
	Settings    string
	Device      string
	Plaintext   string
	ProxyBackup string
	Daemon      string
	PID         string
	Log         string
}

func DefaultPaths() (Paths, error) {
	dir := os.Getenv("EFAN_CONFIG_DIR")
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return Paths{}, err
		}
		dir = filepath.Join(base, "efan")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Paths{}, err
	}
	return Paths{
		Dir:         dir,
		Key:         filepath.Join(dir, "key.pem"),
		Session:     filepath.Join(dir, "session.json"),
		Config:      filepath.Join(dir, "config.yaml"),
		Settings:    filepath.Join(dir, "settings.json"),
		Device:      filepath.Join(dir, "device.json"),
		Plaintext:   filepath.Join(dir, "proxy_plaintext.yaml"),
		ProxyBackup: filepath.Join(dir, "proxy_backup.json"),
		Daemon:      filepath.Join(dir, "daemon.json"),
		PID:         filepath.Join(dir, "efan.pid"),
		Log:         filepath.Join(dir, "efan.log"),
	}, nil
}
