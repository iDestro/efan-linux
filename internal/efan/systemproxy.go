package efan

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var ErrNoGsettings = errors.New("gsettings is not available; set the proxy environment variables manually")

type gsettingValue struct {
	Schema string `json:"schema"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}

type proxyBackup struct {
	Values []gsettingValue `json:"values"`
}

func EnableGNOMEProxy(paths Paths, httpPort, socksPort int) error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return ErrNoGsettings
	}
	keys := []gsettingValue{
		{Schema: "org.gnome.system.proxy", Key: "mode"},
		{Schema: "org.gnome.system.proxy", Key: "use-same-proxy"},
		{Schema: "org.gnome.system.proxy.http", Key: "host"},
		{Schema: "org.gnome.system.proxy.http", Key: "port"},
		{Schema: "org.gnome.system.proxy.https", Key: "host"},
		{Schema: "org.gnome.system.proxy.https", Key: "port"},
		{Schema: "org.gnome.system.proxy.socks", Key: "host"},
		{Schema: "org.gnome.system.proxy.socks", Key: "port"},
	}
	backup := proxyBackup{Values: make([]gsettingValue, 0, len(keys))}
	for _, item := range keys {
		value, err := getGSetting(item.Schema, item.Key)
		if err != nil {
			continue
		}
		item.Value = value
		backup.Values = append(backup.Values, item)
	}
	if len(backup.Values) == 0 {
		return fmt.Errorf("%w (no org.gnome.system.proxy keys found)", ErrNoGsettings)
	}
	if _, err := os.Stat(paths.ProxyBackup); os.IsNotExist(err) {
		if err := writeJSON(paths.ProxyBackup, backup); err != nil {
			return err
		}
	}

	sets := []gsettingValue{
		{Schema: "org.gnome.system.proxy", Key: "mode", Value: "manual"},
		{Schema: "org.gnome.system.proxy", Key: "use-same-proxy", Value: "false"},
		{Schema: "org.gnome.system.proxy.http", Key: "host", Value: "127.0.0.1"},
		{Schema: "org.gnome.system.proxy.http", Key: "port", Value: strconv.Itoa(httpPort)},
		{Schema: "org.gnome.system.proxy.https", Key: "host", Value: "127.0.0.1"},
		{Schema: "org.gnome.system.proxy.https", Key: "port", Value: strconv.Itoa(httpPort)},
		{Schema: "org.gnome.system.proxy.socks", Key: "host", Value: "127.0.0.1"},
		{Schema: "org.gnome.system.proxy.socks", Key: "port", Value: strconv.Itoa(socksPort)},
	}
	for _, item := range sets {
		if err := setGSetting(item.Schema, item.Key, item.Value); err != nil {
			return err
		}
	}
	return nil
}

func DisableGNOMEProxy(paths Paths) error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return ErrNoGsettings
	}
	var backup proxyBackup
	if err := readJSON(paths.ProxyBackup, &backup); err == nil && len(backup.Values) > 0 {
		var firstErr error
		for _, item := range backup.Values {
			if item.Value == "" {
				continue
			}
			if err := setGSetting(item.Schema, item.Key, item.Value); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		_ = os.Remove(paths.ProxyBackup)
		return firstErr
	}
	return setGSetting("org.gnome.system.proxy", "mode", "none")
}

func GNOMEProxyMode() string {
	value, err := getGSetting("org.gnome.system.proxy", "mode")
	if err != nil {
		return "unknown"
	}
	return strings.Trim(value, "'\"")
}

const noProxyValue = "localhost,127.0.0.1,::1"

func PrintProxyEnv(w io.Writer, httpPort, socksPort int) {
	fmt.Fprintf(w, "export http_proxy=http://127.0.0.1:%d\n", httpPort)
	fmt.Fprintf(w, "export https_proxy=http://127.0.0.1:%d\n", httpPort)
	fmt.Fprintf(w, "export all_proxy=socks5h://127.0.0.1:%d\n", socksPort)
	fmt.Fprintf(w, "export HTTP_PROXY=$http_proxy\n")
	fmt.Fprintf(w, "export HTTPS_PROXY=$https_proxy\n")
	fmt.Fprintf(w, "export ALL_PROXY=$all_proxy\n")
	fmt.Fprintf(w, "export no_proxy=%s\n", noProxyValue)
	fmt.Fprintf(w, "export NO_PROXY=$no_proxy\n")
}

// PrintProxyEnvSocksOnly is used when the daemon was started with --no-http.
func PrintProxyEnvSocksOnly(w io.Writer, socksPort int) {
	fmt.Fprintln(w, "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY")
	fmt.Fprintf(w, "export all_proxy=socks5h://127.0.0.1:%d\n", socksPort)
	fmt.Fprintf(w, "export ALL_PROXY=$all_proxy\n")
	fmt.Fprintf(w, "export no_proxy=%s\n", noProxyValue)
	fmt.Fprintf(w, "export NO_PROXY=$no_proxy\n")
}

func PrintProxyUnset(w io.Writer) {
	fmt.Fprintln(w, "unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY")
}

func getGSetting(schema, key string) (string, error) {
	cmd := exec.Command("gsettings", "get", schema, key)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func setGSetting(schema, key, value string) error {
	cmd := exec.Command("gsettings", "set", schema, key, value)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("gsettings set %s %s: %s", schema, key, msg)
	}
	return nil
}
