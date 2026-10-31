package efan

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// DaemonState is written by a background `efan __daemon` process and read by
// the start/stop/status/on/off commands.
type DaemonState struct {
	PID         int       `json:"pid"`
	Node        string    `json:"node,omitempty"`
	Socks       string    `json:"socks,omitempty"`
	HTTP        string    `json:"http,omitempty"`
	SystemProxy bool      `json:"system_proxy,omitempty"`
	Debug       bool      `json:"debug,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
}

func LoadDaemonState(path string) (DaemonState, error) {
	var state DaemonState
	if err := readJSON(path, &state); err != nil {
		return DaemonState{}, err
	}
	return state, nil
}

func SaveDaemonState(path string, state DaemonState) error {
	if state.StartedAt.IsZero() {
		state.StartedAt = time.Now()
	}
	return writeJSON(path, state)
}

func RemoveDaemonState(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func SavePID(path string, pid int) error {
	return writeFile0600(path, []byte(strconv.Itoa(pid)+"\n"))
}

func LoadPID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}
