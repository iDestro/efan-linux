package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"efan-linux/internal/efan"
	"efan-linux/internal/x365"
)

const (
	defaultSocksAddr = "127.0.0.1:10865"
	defaultHTTPAddr  = "127.0.0.1:10866"
)

type startOptions struct {
	Node        string
	Listen      string
	HTTPListen  string
	NoHTTP      bool
	SystemProxy bool
	Debug       bool
}

type startFlagValues struct {
	node        *string
	listen      *string
	httpListen  *string
	noHTTP      *bool
	systemProxy *bool
	debug       *bool
}

func registerStartFlags(fs *flag.FlagSet) *startFlagValues {
	return &startFlagValues{
		node:        fs.String("node", "", "node name or 1-based index"),
		listen:      fs.String("listen", "", "SOCKS5 listen address (default from settings)"),
		httpListen:  fs.String("http-listen", "", "HTTP proxy listen address (default from settings)"),
		noHTTP:      fs.Bool("no-http", false, "do not start the local HTTP proxy"),
		systemProxy: fs.Bool("system-proxy", false, "set the GNOME system proxy while running"),
		debug:       fs.Bool("debug", false, "verbose connection logs"),
	}
}

func (f *startFlagValues) options() startOptions {
	return startOptions{
		Node:        *f.node,
		Listen:      *f.listen,
		HTTPListen:  *f.httpListen,
		NoHTTP:      *f.noHTTP,
		SystemProxy: *f.systemProxy,
		Debug:       *f.debug,
	}
}

func wasFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func resolveStartOptions(paths efan.Paths, opts startOptions) (startOptions, x365.Node, error) {
	settings, err := efan.LoadSettings(paths.Settings)
	if err != nil {
		return startOptions{}, x365.Node{}, err
	}
	cfg, err := x365.LoadConfig(paths.Config)
	if err != nil {
		return startOptions{}, x365.Node{}, fmt.Errorf("load %s: %w (run 'efan login' first)", paths.Config, err)
	}
	node, err := selectNode(cfg, opts.Node, opts.Node == "", settings.SelectedNode)
	if err != nil {
		return startOptions{}, x365.Node{}, err
	}
	socksAddr := strings.TrimSpace(opts.Listen)
	if socksAddr == "" {
		socksAddr = settings.Listen
	}
	if socksAddr == "" {
		socksAddr = defaultSocksAddr
	}
	httpAddr := strings.TrimSpace(opts.HTTPListen)
	if httpAddr == "" {
		httpAddr = settings.HTTPListen
	}
	if httpAddr == "" {
		httpAddr = defaultHTTPAddr
	}
	if opts.SystemProxy && opts.NoHTTP {
		return startOptions{}, x365.Node{}, errors.New("--system-proxy needs the HTTP proxy; remove --no-http")
	}
	opts.Node = node.Name
	opts.Listen = socksAddr
	opts.HTTPListen = httpAddr
	return opts, node, nil
}

func daemonPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	// Avoid treating a recycled PID as our daemon.
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		return strings.Contains(cmdline, "__daemon")
	}
	return true
}

func runningDaemon(paths efan.Paths) (*efan.DaemonState, error) {
	state, err := efan.LoadDaemonState(paths.Daemon)
	if err == nil {
		if daemonPIDAlive(state.PID) {
			return &state, nil
		}
		return nil, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	pid, pidErr := efan.LoadPID(paths.PID)
	if pidErr == nil && daemonPIDAlive(pid) {
		return &efan.DaemonState{PID: pid}, nil
	}
	return nil, nil
}

// cleanupStaleDaemon removes state left behind by a killed daemon and restores
// the GNOME proxy if the daemon did not get a chance to do it itself.
func cleanupStaleDaemon(paths efan.Paths) {
	state, err := efan.LoadDaemonState(paths.Daemon)
	if err == nil {
		if daemonPIDAlive(state.PID) {
			return
		}
		if state.SystemProxy {
			_ = efan.DisableGNOMEProxy(paths)
		}
		_ = efan.RemoveDaemonState(paths.Daemon)
		_ = os.Remove(paths.PID)
		return
	}
	if !os.IsNotExist(err) {
		if pid, pidErr := efan.LoadPID(paths.PID); pidErr == nil && daemonPIDAlive(pid) {
			return
		}
		_ = efan.RemoveDaemonState(paths.Daemon)
		_ = os.Remove(paths.PID)
		return
	}
	if pid, pidErr := efan.LoadPID(paths.PID); pidErr == nil && !daemonPIDAlive(pid) {
		_ = os.Remove(paths.PID)
	} else if pidErr != nil && !os.IsNotExist(pidErr) {
		_ = os.Remove(paths.PID)
	}
}

func ensurePortFree(addr string) error {
	if portOf(addr, 0) == 0 {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("already in use (%v); stop a foreground 'efan connect' first", err)
	}
	_ = ln.Close()
	return nil
}

func ensureStartPortsFree(opts startOptions) error {
	if err := ensurePortFree(opts.Listen); err != nil {
		return fmt.Errorf("SOCKS5 %s: %w", opts.Listen, err)
	}
	if !opts.NoHTTP {
		if err := ensurePortFree(opts.HTTPListen); err != nil {
			return fmt.Errorf("HTTP %s: %w", opts.HTTPListen, err)
		}
	}
	return nil
}

func tailLog(path string, lines int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if lines > 0 && len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

func tcpReachable(addr string, timeout time.Duration) bool {
	if addr == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func spawnDaemon(paths efan.Paths, opts startOptions) (efan.DaemonState, error) {
	exe, err := os.Executable()
	if err != nil {
		return efan.DaemonState{}, err
	}
	args := []string{"__daemon", "--node", opts.Node, "--listen", opts.Listen}
	if opts.NoHTTP {
		args = append(args, "--no-http")
	} else {
		args = append(args, "--http-listen", opts.HTTPListen)
	}
	if opts.SystemProxy {
		args = append(args, "--system-proxy")
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	logFile, err := os.OpenFile(paths.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return efan.DaemonState{}, fmt.Errorf("open daemon log: %w", err)
	}
	if _, err := fmt.Fprintf(logFile, "\n===== %s starting daemon =====\n", time.Now().Format(time.RFC3339)); err != nil {
		logFile.Close()
		return efan.DaemonState{}, err
	}

	cmd := exec.Command(exe, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return efan.DaemonState{}, fmt.Errorf("start daemon: %w", err)
	}
	_ = logFile.Close()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if state, err := efan.LoadDaemonState(paths.Daemon); err == nil && state.PID == cmd.Process.Pid && daemonPIDAlive(state.PID) {
			if tcpReachable(state.Socks, 500*time.Millisecond) {
				return state, nil
			}
		}
		select {
		case err := <-waitCh:
			if err == nil {
				err = errors.New("process exited")
			}
			return efan.DaemonState{}, fmt.Errorf("daemon exited before it was ready: %v\n%s", err, tailLog(paths.Log, 20))
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			return efan.DaemonState{}, fmt.Errorf("daemon did not become ready within 15s; see %s\n%s", paths.Log, tailLog(paths.Log, 20))
		}
	}
}

func stopDaemon(paths efan.Paths, force bool) (bool, error) {
	state, err := runningDaemon(paths)
	if err != nil {
		return false, err
	}
	if state == nil {
		_ = efan.RemoveDaemonState(paths.Daemon)
		_ = os.Remove(paths.PID)
		return false, nil
	}
	pid := state.PID
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			_ = efan.RemoveDaemonState(paths.Daemon)
			_ = os.Remove(paths.PID)
			return false, nil
		}
		return false, fmt.Errorf("stop daemon pid %d: %w", pid, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !daemonPIDAlive(pid) {
			_ = efan.RemoveDaemonState(paths.Daemon)
			_ = os.Remove(paths.PID)
			if _, statErr := os.Stat(paths.ProxyBackup); statErr == nil {
				_ = efan.DisableGNOMEProxy(paths)
			}
			return true, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !force {
		return false, fmt.Errorf("daemon pid %d did not stop within 10s (use --force)", pid)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	for i := 0; i < 20 && daemonPIDAlive(pid); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if daemonPIDAlive(pid) {
		return false, fmt.Errorf("daemon pid %d is still alive after SIGKILL", pid)
	}
	_ = efan.RemoveDaemonState(paths.Daemon)
	_ = os.Remove(paths.PID)
	if _, statErr := os.Stat(paths.ProxyBackup); statErr == nil {
		_ = efan.DisableGNOMEProxy(paths)
	}
	return true, nil
}

func daemonPorts(state *efan.DaemonState) (httpPort, socksPort int) {
	httpPort = 10866
	socksPort = 10865
	if state != nil {
		httpPort = portOf(state.HTTP, httpPort)
		socksPort = portOf(state.Socks, socksPort)
	}
	return httpPort, socksPort
}

func printDaemonSummary(state *efan.DaemonState, paths efan.Paths, already bool) {
	if already {
		fmt.Printf("Daemon already running (pid %d).\n", state.PID)
	} else {
		fmt.Println("Daemon started.")
	}
	node := state.Node
	if node == "" {
		node = "unknown"
	}
	fmt.Printf("  PID:    %d\n", state.PID)
	fmt.Printf("  Node:   %s\n", node)
	if state.Socks != "" {
		fmt.Printf("  SOCKS5: %s\n", state.Socks)
	} else {
		fmt.Println("  SOCKS5: unknown")
	}
	if state.HTTP != "" {
		fmt.Printf("  HTTP:   %s\n", state.HTTP)
	} else {
		fmt.Println("  HTTP:   disabled")
	}
	if state.SystemProxy {
		fmt.Println("  GNOME:  enabled")
	} else {
		fmt.Println("  GNOME:  not changed (browsers need 'efan on')")
	}
	if !state.StartedAt.IsZero() {
		fmt.Printf("  Uptime: %s\n", time.Since(state.StartedAt).Round(time.Second))
	}
	fmt.Printf("  Log:    %s\n", paths.Log)
	if !already {
		fmt.Println("\nTerminal proxy: efan on")
	}
}

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sf := registerStartFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	cleanupStaleDaemon(paths)
	opts, _, err := resolveStartOptions(paths, sf.options())
	if err != nil {
		return err
	}
	state, err := runningDaemon(paths)
	if err != nil {
		return err
	}
	if state != nil {
		if wasFlagSet(fs, "node") && state.Node != "" && state.Node != opts.Node {
			return fmt.Errorf("daemon already running on %q; use 'efan restart --node %q'", state.Node, opts.Node)
		}
		printDaemonSummary(state, paths, true)
		return nil
	}
	if err := ensureStartPortsFree(opts); err != nil {
		return err
	}
	started, err := spawnDaemon(paths, opts)
	if err != nil {
		return err
	}
	printDaemonSummary(&started, paths, false)
	return nil
}

func cmdStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", false, "kill the daemon if it does not stop normally")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	cleanupStaleDaemon(paths)
	stopped, err := stopDaemon(paths, *force)
	if err != nil {
		return err
	}
	if stopped {
		fmt.Println("Daemon stopped.")
	} else {
		fmt.Println("Daemon is not running.")
	}
	return nil
}

func cmdRestart(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sf := registerStartFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	cleanupStaleDaemon(paths)
	opts := sf.options()
	state, err := runningDaemon(paths)
	if err != nil {
		return err
	}
	if state != nil {
		if !wasFlagSet(fs, "node") && opts.Node == "" {
			opts.Node = state.Node
		}
		if !wasFlagSet(fs, "listen") {
			opts.Listen = state.Socks
		}
		if !wasFlagSet(fs, "http-listen") {
			opts.HTTPListen = state.HTTP
		}
		if !wasFlagSet(fs, "no-http") {
			opts.NoHTTP = state.HTTP == ""
		}
		if !wasFlagSet(fs, "system-proxy") {
			opts.SystemProxy = state.SystemProxy
		}
		if !wasFlagSet(fs, "debug") {
			opts.Debug = state.Debug
		}
	}
	// Resolve before stopping so a bad node/config does not leave the user offline.
	opts, _, err = resolveStartOptions(paths, opts)
	if err != nil {
		return err
	}
	if state != nil {
		if _, err := stopDaemon(paths, false); err != nil {
			return err
		}
		fmt.Println("Daemon stopped.")
	}
	if err := ensureStartPortsFree(opts); err != nil {
		return err
	}
	started, err := spawnDaemon(paths, opts)
	if err != nil {
		return err
	}
	printDaemonSummary(&started, paths, false)
	return nil
}

func cmdOn(args []string) error {
	fs := flag.NewFlagSet("on", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sf := registerStartFlags(fs)
	fs.Lookup("system-proxy").Usage = "enable the GNOME system proxy (default for 'efan on')"
	noSystemProxy := fs.Bool("no-system-proxy", false, "do not use the GNOME system proxy; set the terminal proxy only")
	if err := fs.Parse(args); err != nil {
		return err
	}
	enableSystemProxy := true
	if *noSystemProxy || (wasFlagSet(fs, "system-proxy") && !*sf.systemProxy) {
		enableSystemProxy = false
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	cleanupStaleDaemon(paths)
	state, err := runningDaemon(paths)
	if err != nil {
		return err
	}
	if state == nil {
		opts := sf.options()
		opts.SystemProxy = enableSystemProxy
		if opts.NoHTTP && !wasFlagSet(fs, "system-proxy") && !*noSystemProxy {
			opts.SystemProxy = false
		}
		opts, _, err = resolveStartOptions(paths, opts)
		if err != nil {
			return err
		}
		if err := ensureStartPortsFree(opts); err != nil {
			return err
		}
		started, err := spawnDaemon(paths, opts)
		if err != nil {
			return err
		}
		state = &started
		fmt.Fprintf(os.Stderr, "Started daemon on %s (pid %d).\n", state.Node, state.PID)
	} else {
		if wasFlagSet(fs, "node") {
			checkOpts := sf.options()
			checkOpts.SystemProxy = false
			opts, _, err := resolveStartOptions(paths, checkOpts)
			if err != nil {
				return err
			}
			if state.Node != "" && state.Node != opts.Node {
				return fmt.Errorf("daemon already running on %q; use 'efan restart --node %q'", state.Node, opts.Node)
			}
		}
		fmt.Fprintf(os.Stderr, "Using daemon on %s (pid %d).\n", state.Node, state.PID)
	}
	httpPort, socksPort := daemonPorts(state)
	if enableSystemProxy {
		if state.HTTP == "" {
			fmt.Fprintln(os.Stderr, "GNOME system proxy: not changed (HTTP proxy is disabled)")
		} else if err := efan.EnableGNOMEProxy(paths, httpPort, socksPort); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not enable the GNOME system proxy: %v\n", err)
		} else {
			if !state.SystemProxy {
				if err := updateDaemonSystemProxy(paths, true); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not update daemon state: %v\n", err)
				}
				state.SystemProxy = true
			}
			fmt.Fprintf(os.Stderr, "GNOME system proxy: on (HTTP 127.0.0.1:%d)\n", httpPort)
		}
	} else if state.SystemProxy {
		if err := efan.DisableGNOMEProxy(paths); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not disable the GNOME system proxy: %v\n", err)
		} else {
			if err := updateDaemonSystemProxy(paths, false); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not update daemon state: %v\n", err)
			}
			state.SystemProxy = false
			fmt.Fprintln(os.Stderr, "GNOME system proxy: off")
		}
	} else {
		fmt.Fprintln(os.Stderr, "GNOME system proxy: unchanged (terminal only)")
	}
	if state.HTTP != "" {
		efan.PrintProxyEnv(os.Stdout, httpPort, socksPort)
	} else {
		efan.PrintProxyEnvSocksOnly(os.Stdout, socksPort)
	}
	if os.Getenv("EFAN_SHELL_WRAPPER") != "1" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, `To apply in this shell: eval "$(efan on)"`)
		fmt.Fprintln(os.Stderr, "Shell integration: source ~/.config/efan/shell/efan.sh")
	}
	return nil
}

func cmdOff(args []string) error {
	fs := flag.NewFlagSet("off", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	stop := fs.Bool("stop", true, "stop the background daemon (default)")
	keepDaemon := fs.Bool("keep-daemon", false, "leave the background daemon running")
	if err := fs.Parse(args); err != nil {
		return err
	}
	efan.PrintProxyUnset(os.Stdout)
	paths, pathErr := efan.DefaultPaths()
	if pathErr != nil {
		fmt.Fprintln(os.Stderr, "Terminal proxy disabled.")
		return nil
	}
	cleanupStaleDaemon(paths)
	state, stateErr := runningDaemon(paths)
	if *stop && !*keepDaemon {
		stopped, err := stopDaemon(paths, false)
		if err != nil {
			return err
		}
		if stopped {
			fmt.Fprintln(os.Stderr, "Daemon stopped.")
		} else {
			fmt.Fprintln(os.Stderr, "Daemon is not running.")
			if _, statErr := os.Stat(paths.ProxyBackup); statErr == nil {
				if err := efan.DisableGNOMEProxy(paths); err != nil {
					fmt.Fprintf(os.Stderr, "warning: could not restore the GNOME proxy: %v\n", err)
				} else {
					fmt.Fprintln(os.Stderr, "GNOME system proxy restored.")
				}
			}
		}
	} else {
		proxyManaged := false
		if stateErr == nil && state != nil && state.SystemProxy {
			proxyManaged = true
		}
		if _, statErr := os.Stat(paths.ProxyBackup); statErr == nil {
			proxyManaged = true
		}
		if proxyManaged {
			if err := efan.DisableGNOMEProxy(paths); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not restore the GNOME proxy: %v\n", err)
			} else {
				if stateErr == nil && state != nil && state.SystemProxy {
					if err := updateDaemonSystemProxy(paths, false); err != nil {
						fmt.Fprintf(os.Stderr, "warning: could not update daemon state: %v\n", err)
					}
				}
				fmt.Fprintln(os.Stderr, "GNOME system proxy disabled.")
			}
		}
		switch {
		case stateErr != nil:
			fmt.Fprintf(os.Stderr, "Terminal proxy disabled; daemon state error: %v\n", stateErr)
		case state == nil:
			fmt.Fprintln(os.Stderr, "Terminal proxy disabled; daemon is not running.")
		default:
			fmt.Fprintln(os.Stderr, "Terminal proxy disabled; daemon left running (--keep-daemon).")
		}
	}
	if os.Getenv("EFAN_SHELL_WRAPPER") != "1" {
		fmt.Fprintln(os.Stderr, `To apply in this shell: eval "$(efan off)"`)
	}
	return nil
}

func cmdLog(args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	follow := fs.Bool("f", false, "follow new log output")
	lines := fs.Int("n", 50, "number of lines to show (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	f, err := os.Open(paths.Log)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("no daemon log yet; start the tunnel with 'efan start'")
		}
		return err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if *lines > 0 {
		parts := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		if len(parts) > *lines {
			parts = parts[len(parts)-*lines:]
		}
		if len(parts) > 0 && (len(parts) > 1 || parts[0] != "") {
			fmt.Println(strings.Join(parts, "\n"))
		}
	} else if len(data) > 0 {
		fmt.Print(string(data))
	}
	if !*follow {
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	buf := make([]byte, 32*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(300 * time.Millisecond):
		}
	}
}
