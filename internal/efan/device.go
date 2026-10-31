package efan

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"time"
)

const (
	DefaultAppVersion = "1.0.68"
	defaultOSVersion  = "26.1.30"
	defaultCoreVer    = "26.1.30"
	defaultConfigVer  = "25.11.20"
)

// DeviceInfo mirrors api.DeviceInfo in client.dll. The JSON field names and
// types are taken from the Go type metadata; keeping the full schema makes the
// RSA-signed x-sig header look like the real Windows client's.
type DeviceInfo struct {
	AppName       string `json:"app_name"`
	DeviceName    string `json:"device_name"`
	Fit           int64  `json:"fit"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	AppVersion    string `json:"app_version"`
	OSArch        string `json:"os_arch"`
	ClientIP      string `json:"client_ip"`
	Api           string `json:"api"`
	Proxy         bool   `json:"proxy"`
	Did           string `json:"did"`
	Dns           string `json:"dns"`
	ConfigVersion string `json:"config_version"`
	CoreVersion   string `json:"core_version"`
	ScreenWidth   string `json:"screen_width"`
	ScreenHeight  string `json:"screen_height"`
	Language      string `json:"language"`
	Fp            string `json:"fp"`
	FcmToken      string `json:"fcm_token"`
	BuildID       string `json:"build_id"`
	IsEmulator    bool   `json:"is_emulator"`
	BuildNumber   string `json:"build_number"`
	PackageName   string `json:"package_name"`
}

func BuildDeviceInfo(settings Settings, did, apiBase string) DeviceInfo {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	appVersion := settings.AppVersion
	if appVersion == "" {
		appVersion = DefaultAppVersion
	}
	fit := settings.Fit
	if fit == 0 {
		fit = time.Now().UnixMilli()
	}
	arch := runtime.GOARCH
	if arch != "arm64" {
		arch = "amd64"
	}
	return DeviceInfo{
		AppName:       "efanapp",
		DeviceName:    url.QueryEscape(hostname),
		Fit:           fit,
		OS:            "win32",
		OSVersion:     defaultOSVersion,
		AppVersion:    appVersion,
		OSArch:        arch,
		ClientIP:      "",
		Api:           apiBase,
		Proxy:         false,
		Did:           did,
		Dns:           "tcp-tls",
		ConfigVersion: defaultConfigVer,
		CoreVersion:   defaultCoreVer,
		ScreenWidth:   "0",
		ScreenHeight:  "0",
		Language:      "zh-CN",
		Fp:            "",
		FcmToken:      "",
		BuildID:       appVersion,
		IsEmulator:    false,
		BuildNumber:   "",
		PackageName:   "efanapp",
	}
}

// Sign produces the x-sig value: the DeviceInfo JSON encrypted with the
// public half of the embedded RSA key, split into 200-byte chunks, using
// PKCS#1 v1.5 and standard base64.
func (d DeviceInfo) Sign(key *rsa.PrivateKey) (string, error) {
	payload, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	const chunkSize = 200
	var out []byte
	for len(payload) > 0 {
		n := chunkSize
		if len(payload) < n {
			n = len(payload)
		}
		block, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, payload[:n])
		if err != nil {
			return "", err
		}
		out = append(out, block...)
		payload = payload[n:]
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

func DeviceHeaders(info DeviceInfo, key *rsa.PrivateKey) (map[string]string, error) {
	sig, err := info.Sign(key)
	if err != nil {
		return nil, fmt.Errorf("sign device info: %w", err)
	}
	return map[string]string{
		"x-did": info.Did,
		"x-sig": sig,
	}, nil
}
