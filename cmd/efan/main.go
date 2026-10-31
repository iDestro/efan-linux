package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"efan-linux/internal/efan"
	"efan-linux/internal/x365"
)

const clientVersion = "0.2.5"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		return
	}
	command := os.Args[1]
	args := os.Args[2:]
	var err error
	switch command {
	case "login":
		err = cmdLogin(args)
	case "refresh":
		err = cmdRefresh(args)
	case "fetch", "update":
		err = cmdFetch(args)
	case "list", "nodes":
		err = cmdList(args)
	case "connect":
		err = cmdConnect(args)
	case "start":
		err = cmdStart(args)
	case "stop":
		err = cmdStop(args)
	case "restart":
		err = cmdRestart(args)
	case "on":
		err = cmdOn(args)
	case "off":
		err = cmdOff(args)
	case "node":
		err = cmdNode(args)
	case "log", "logs":
		err = cmdLog(args)
	case "test", "probe", "bench":
		err = cmdTest(args)
	case "proxy":
		err = cmdProxy(args)
	case "status":
		err = cmdStatus(args)
	case "clash", "sub", "subscription":
		err = cmdClash(args)
	case "whmcs", "sso":
		err = cmdWhmcs(args)
	case "logout":
		err = cmdLogout(args)
	case "extract-key":
		err = cmdExtractKey(args)
	case "__daemon":
		err = cmdConnect(append([]string{"--daemon"}, args...))
	case "version", "--version", "-v":
		fmt.Printf("efan-native %s (%s/%s, %s)\n", clientVersion, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "efan: unknown command %q\n\n", command)
		usage()
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintf(os.Stderr, "efan: %v\n", friendlyError(err))
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`efan-native - use an Efan account on Linux without the Windows GUI

Usage:
  efan login [--email EMAIL] [--password-stdin] [--no-device-headers]
  efan refresh
  efan fetch
  efan list [--json]
  efan start [--node NAME|INDEX] [--listen ADDR] [--http-listen ADDR]
             [--no-http] [--system-proxy] [--debug]
  efan stop [--force]
  efan restart [--node NAME|INDEX] [--listen ADDR] [--http-listen ADDR]
               [--no-http] [--system-proxy] [--debug]
  efan on [--node NAME|INDEX] [--no-system-proxy]
  efan off [--keep-daemon]
  efan node [--filter TEXT] [--no-restart]
  efan node ls [--filter TEXT]
  efan node use [NAME|INDEX] [--filter TEXT] [--no-restart] [--no-test]
  efan log [-f] [-n LINES]
  efan connect [--node NAME|INDEX] [--listen ADDR] [--http-listen ADDR]
               [--no-http] [--system-proxy] [--debug]
  efan test [--node NAME|INDEX] [--filter TEXT] [--limit N]
            [--concurrency N] [--timeout DURATION] [--retries N]
            [--target HOST:PORT] [--json] [--save]
  efan proxy on [--http-port PORT] [--socks-port PORT]
  efan proxy off
  efan proxy status
  efan proxy env
  efan status
  efan clash [--json] [--base URL]
  efan whmcs
  efan logout [--all]
  efan extract-key [--dll PATH] [--out PATH]
  efan version

Login writes account tokens and nodes under ~/.config/efan (mode 0600).
The node config is produced by decrypting the account's proxy payload with
the RSA key embedded in the official Windows client.

Environment:
  EFAN_CONFIG_DIR   override ~/.config/efan
  EFAN_CLIENT_DLL   path to client.dll for automatic key extraction
  EFAN_API_BASE     override https://api.efanapp.com
  EFAN_CLASH_BASE   override https://api.efanyunapi.com/clash
  EFAN_APP_VERSION  app version reported to the API (default 1.0.68)
  EFAN_DID          reuse a device id (if your plan has a device limit)
`)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func loadClient(apiBase, appVersion string, debug, noDeviceHeaders bool) (*efan.APIClient, efan.Settings, efan.Paths, error) {
	paths, err := efan.DefaultPaths()
	if err != nil {
		return nil, efan.Settings{}, efan.Paths{}, err
	}
	key, err := efan.EnsureKey(paths, os.Getenv("EFAN_CLIENT_DLL"))
	if err != nil {
		return nil, efan.Settings{}, paths, err
	}
	settings, err := efan.LoadSettings(paths.Settings)
	if err != nil {
		return nil, efan.Settings{}, paths, err
	}
	if didOverride := strings.TrimSpace(os.Getenv("EFAN_DID")); didOverride != "" {
		settings.Did = didOverride
	}
	did, err := efan.EnsureDID(&settings)
	if err != nil {
		return nil, efan.Settings{}, paths, err
	}
	if appVersion != "" {
		settings.AppVersion = appVersion
	}
	if settings.AppVersion == "" {
		settings.AppVersion = efan.DefaultAppVersion
	}
	if settings.Fit == 0 {
		settings.Fit = time.Now().UnixMilli()
	}
	if err := efan.SaveSettings(paths.Settings, settings); err != nil {
		return nil, efan.Settings{}, paths, err
	}
	device := efan.BuildDeviceInfo(settings, did, apiBase)
	client := efan.NewAPIClient(apiBase, key, device)
	client.Debug = debug
	client.NoDeviceHeaders = noDeviceHeaders
	return client, settings, paths, nil
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	emailFlag := fs.String("email", "", "account email")
	passwordFlag := fs.String("password", "", "account password (prefer interactive input)")
	passwordStdin := fs.Bool("password-stdin", false, "read the password from stdin")
	noDevice := fs.Bool("no-device-headers", false, "do not send x-did/x-sig headers")
	apiBase := fs.String("api-base", envOr("EFAN_API_BASE", efan.DefaultAPIBase), "API base URL")
	appVersion := fs.String("app-version", envOr("EFAN_APP_VERSION", efan.DefaultAppVersion), "app version reported to the API")
	debug := fs.Bool("debug", false, "verbose diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}

	email := strings.TrimSpace(*emailFlag)
	var err error
	if email == "" {
		email, err = promptLine("Email: ")
		if err != nil {
			return err
		}
	}
	password := *passwordFlag
	if password == "" {
		if *passwordStdin {
			data, readErr := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
			if readErr != nil {
				return readErr
			}
			password = strings.TrimSpace(string(data))
		} else {
			password, err = readPassword()
			if err != nil {
				return err
			}
		}
	}
	if email == "" || password == "" {
		return errors.New("email and password are required")
	}

	client, settings, paths, err := loadClient(*apiBase, *appVersion, *debug, *noDevice)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := client.Login(ctx, email, password)
	if err != nil && !*noDevice && isSignatureError(err) {
		fmt.Fprintln(os.Stderr, "device signature was rejected; retrying without x-did/x-sig")
		client.NoDeviceHeaders = true
		result, err = client.Login(ctx, email, password)
	}
	if err != nil {
		return err
	}

	session := result.Session
	captureSessionCookie(client, &session)
	if err := efan.SaveSession(paths.Session, session); err != nil {
		return err
	}
	settings.AppVersion = client.Device.AppVersion
	if err := efan.SaveSettings(paths.Settings, settings); err != nil {
		return err
	}
	printSession(session)
	fmt.Println()

	nodes, err := fetchAppData(ctx, client, paths, &session, &settings, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: login succeeded, but the app data could not be loaded: %v\n", friendlyError(err))
		fmt.Fprintln(os.Stderr, "You can retry with: efan fetch")
		return nil
	}
	fmt.Printf("Ready: %d nodes written to %s\n", nodes, paths.Config)
	return nil
}

func cmdRefresh(args []string) error {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiBase := fs.String("api-base", envOr("EFAN_API_BASE", efan.DefaultAPIBase), "API base URL")
	appVersion := fs.String("app-version", envOr("EFAN_APP_VERSION", efan.DefaultAppVersion), "app version reported to the API")
	debug := fs.Bool("debug", false, "verbose diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, settings, paths, err := loadClient(*apiBase, *appVersion, *debug, false)
	if err != nil {
		return err
	}
	session, err := loadSession(paths)
	if err != nil {
		return err
	}
	if session.SessionToken == "" && session.Cookie == "" {
		return errors.New("no session token stored; run 'efan login' again")
	}
	if sessionNeedsCookie(session) {
		return errors.New("stored session has no API cookie (created by an older efan); run 'efan login' once")
	}
	if err := applySessionCookie(client, &session); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	refreshed, _, err := client.Refresh(ctx, session.SessionToken)
	if err != nil {
		return fmt.Errorf("refresh failed: %w", err)
	}
	mergeSession(&session, &refreshed)
	captureSessionCookie(client, &session)
	if err := efan.SaveSession(paths.Session, session); err != nil {
		return err
	}
	printSession(session)
	nodes, err := fetchAppData(ctx, client, paths, &session, &settings, false)
	if err != nil {
		return err
	}
	fmt.Printf("Ready: %d nodes written to %s\n", nodes, paths.Config)
	return nil
}

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiBase := fs.String("api-base", envOr("EFAN_API_BASE", efan.DefaultAPIBase), "API base URL")
	appVersion := fs.String("app-version", envOr("EFAN_APP_VERSION", efan.DefaultAppVersion), "app version reported to the API")
	debug := fs.Bool("debug", false, "verbose diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, settings, paths, err := loadClient(*apiBase, *appVersion, *debug, false)
	if err != nil {
		return err
	}
	session, err := loadSession(paths)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	nodes, err := fetchAppData(ctx, client, paths, &session, &settings, false)
	if err != nil {
		return err
	}
	fmt.Printf("Ready: %d nodes written to %s\n", nodes, paths.Config)
	return nil
}

// requestAppData fetches /v1/app, retries transparently after a device-signature
// or expired-session error, and persists any rotated session fields. It is
// shared by "fetch" and "clash" so both commands handle auth consistently.
func requestAppData(ctx context.Context, client *efan.APIClient, paths efan.Paths, session *efan.Session) (efan.AppDataResult, error) {
	if err := applySessionCookie(client, session); err != nil {
		return efan.AppDataResult{}, err
	}
	result, err := client.AppData(ctx, session.AccessToken)
	if err != nil && isSignatureError(err) {
		fmt.Fprintln(os.Stderr, "device signature was rejected; retrying without x-did/x-sig")
		client.NoDeviceHeaders = true
		result, err = client.AppData(ctx, session.AccessToken)
	}
	if err != nil && efan.IsAuthError(err) && (session.SessionToken != "" || session.Cookie != "") {
		refreshed, _, refreshErr := client.Refresh(ctx, session.SessionToken)
		if refreshErr != nil {
			return result, fmt.Errorf("session expired (%v); run 'efan login' again", refreshErr)
		}
		mergeSession(session, &refreshed)
		captureSessionCookie(client, session)
		if saveErr := efan.SaveSession(paths.Session, *session); saveErr != nil {
			return result, saveErr
		}
		result, err = client.AppData(ctx, session.AccessToken)
	}
	if err != nil {
		return result, err
	}
	if result.AccessToken != "" {
		session.AccessToken = result.AccessToken
	}
	if result.SessionToken != "" {
		session.SessionToken = result.SessionToken
	}
	if len(result.Services) > 0 {
		session.Services = result.Services
	}
	captureSessionCookie(client, session)
	if err := efan.SaveSession(paths.Session, *session); err != nil {
		return result, err
	}
	return result, nil
}

func fetchAppData(ctx context.Context, client *efan.APIClient, paths efan.Paths, session *efan.Session, settings *efan.Settings, quiet bool) (int, error) {
	result, err := requestAppData(ctx, client, paths, session)
	if err != nil {
		if errors.Is(err, efan.ErrNoProxy) {
			return 0, errors.New("the account has no available service (proxy field is empty); check that the plan is active and not expired")
		}
		return 0, err
	}

	plain, err := efan.DecryptProxy(result.Proxy, client.Key)
	if err != nil {
		return 0, fmt.Errorf("decrypt proxy payload: %w", err)
	}
	nodes, err := efan.WriteProxyConfig(paths.Config, paths.Plaintext, plain)
	if err != nil {
		return 0, err
	}
	if settings.SelectedNode == "" {
		if cfg, loadErr := x365.LoadConfig(paths.Config); loadErr == nil && len(cfg.Nodes) > 0 {
			settings.SelectedNode = cfg.Nodes[0].Name
			_ = efan.SaveSettings(paths.Settings, *settings)
		}
	}
	if !quiet {
		fmt.Printf("Updated %s (%d nodes).\n", paths.Config, nodes)
	}
	return nodes, nil
}

func cmdClash(args []string) error {
	fs := flag.NewFlagSet("clash", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiBase := fs.String("api-base", envOr("EFAN_API_BASE", efan.DefaultAPIBase), "API base URL")
	appVersion := fs.String("app-version", envOr("EFAN_APP_VERSION", efan.DefaultAppVersion), "app version reported to the API")
	base := fs.String("base", envOr("EFAN_CLASH_BASE", efan.DefaultClashBase), "Clash subscription base URL")
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	debug := fs.Bool("debug", false, "verbose diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client, _, paths, err := loadClient(*apiBase, *appVersion, *debug, false)
	if err != nil {
		return err
	}
	session, err := loadSession(paths)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := requestAppData(ctx, client, paths, &session)
	if err != nil && !errors.Is(err, efan.ErrNoProxy) {
		return err
	}

	serviceID := result.ServiceID
	subscribeToken := result.SubscribeToken
	// Older sessions have no per-service subscribe token, and /v1/app may
	// omit one of the fields. Fill gaps from the login metadata.
	for _, svc := range session.Services {
		if serviceID == "" && svc.ServiceID != "" {
			serviceID = svc.ServiceID
		}
		if subscribeToken == "" && svc.SubscribeToken != "" {
			subscribeToken = svc.SubscribeToken
		}
	}
	if serviceID == "" || subscribeToken == "" {
		if errors.Is(err, efan.ErrNoProxy) {
			return errors.New("no active service was found; check that the plan is active and not expired")
		}
		return errors.New("subscription details are incomplete; run 'efan fetch' or 'efan login' again")
	}
	url, err := efan.ClashSubscriptionURL(*base, serviceID, subscribeToken)
	if err != nil {
		return err
	}
	if *asJSON {
		out := struct {
			ServiceID string `json:"service_id"`
			URL       string `json:"url"`
		}{ServiceID: serviceID, URL: url}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(url)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	cfg, err := x365.LoadConfig(paths.Config)
	if err != nil {
		return fmt.Errorf("load %s: %w (run 'efan login' first)", paths.Config, err)
	}
	settings, _ := efan.LoadSettings(paths.Settings)
	if *asJSON {
		type entry struct {
			Index  int    `json:"index"`
			Name   string `json:"name"`
			Server string `json:"server"`
			Port   int    `json:"port"`
		}
		list := make([]entry, 0, len(cfg.Nodes))
		for i, node := range cfg.Nodes {
			list = append(list, entry{Index: i + 1, Name: node.Name, Server: node.Server, Port: node.Port})
		}
		data, err := json.MarshalIndent(list, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	fmt.Printf("Available nodes (%d) from %s\n", len(cfg.Nodes), paths.Config)
	for i, node := range cfg.Nodes {
		marker := " "
		if settings.SelectedNode == node.Name {
			marker = "*"
		}
		fmt.Printf("%s %3d. %-24s %s:%d\n", marker, i+1, node.Name, node.Server, node.Port)
	}
	return nil
}

func cmdConnect(args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	nodeQuery := fs.String("node", "", "node name or 1-based index")
	listenFlag := fs.String("listen", "", "SOCKS5 listen address (default 127.0.0.1:10865)")
	httpListenFlag := fs.String("http-listen", "", "HTTP proxy listen address (default 127.0.0.1:10866)")
	noHTTP := fs.Bool("no-http", false, "do not start the local HTTP proxy")
	systemProxy := fs.Bool("system-proxy", false, "set the GNOME system proxy while connected")
	debug := fs.Bool("debug", false, "verbose connection logs")
	daemonMode := fs.Bool("daemon", false, "internal: run as a background daemon")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *daemonMode {
		log.SetFlags(log.LstdFlags)
	}
	if *systemProxy && *noHTTP {
		return errors.New("--system-proxy needs the HTTP proxy; remove --no-http")
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	settings, err := efan.LoadSettings(paths.Settings)
	if err != nil {
		return err
	}
	cfg, err := x365.LoadConfig(paths.Config)
	if err != nil {
		return fmt.Errorf("load %s: %w (run 'efan login' first)", paths.Config, err)
	}
	node, err := selectNode(cfg, *nodeQuery, *nodeQuery == "", settings.SelectedNode)
	if err != nil {
		return err
	}
	material, err := x365.MaterialFromUUID(node.UserID)
	if err != nil {
		return fmt.Errorf("node %q has an invalid UUID: %w", node.Name, err)
	}

	socksAddr := *listenFlag
	if socksAddr == "" {
		socksAddr = settings.Listen
	}
	if socksAddr == "" {
		socksAddr = "127.0.0.1:10865"
	}
	httpAddr := *httpListenFlag
	if httpAddr == "" {
		httpAddr = settings.HTTPListen
	}
	if httpAddr == "" {
		httpAddr = "127.0.0.1:10866"
	}

	socksLn, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return fmt.Errorf("listen SOCKS5 on %s: %w", socksAddr, err)
	}
	actualSocks := socksLn.Addr().String()
	var httpLn net.Listener
	if !*noHTTP {
		httpLn, err = net.Listen("tcp", httpAddr)
		if err != nil {
			_ = socksLn.Close()
			return fmt.Errorf("listen HTTP proxy on %s: %w", httpAddr, err)
		}
	}
	actualHTTP := ""
	if httpLn != nil {
		actualHTTP = httpLn.Addr().String()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	logf := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		lower := strings.ToLower(message)
		if *debug || strings.Contains(lower, "fail") || strings.Contains(lower, "error") || strings.Contains(lower, "err=") {
			log.Print(message)
		}
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- x365.ServeSOCKSListener(ctx, socksLn, x365.ServerConfig{
			Node:             node,
			Material:         material,
			Timeout:          20 * time.Second,
			HandshakeTimeout: 15 * time.Second,
			Logf:             logf,
		})
	}()
	if httpLn != nil {
		go func() {
			errCh <- efan.ServeHTTPProxyListener(ctx, httpLn, actualSocks, logf)
		}()
	}

	settings.SelectedNode = node.Name
	settings.Listen = socksAddr
	if httpLn != nil {
		settings.HTTPListen = httpAddr
	}
	_ = efan.SaveSettings(paths.Settings, settings)

	fmt.Printf("Node:   %s (%s:%d)\n", node.Name, node.Server, node.Port)
	fmt.Printf("SOCKS5: %s\n", actualSocks)
	if actualHTTP != "" {
		fmt.Printf("HTTP:   %s\n", actualHTTP)
	} else {
		fmt.Println("HTTP:   disabled")
	}

	enabledSystemProxy := false
	if *systemProxy {
		if err := efan.EnableGNOMEProxy(paths, portOf(actualHTTP, 10866), portOf(actualSocks, 10865)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not set the GNOME system proxy: %v\n", err)
			if !*daemonMode {
				efan.PrintProxyEnv(os.Stderr, portOf(actualHTTP, 10866), portOf(actualSocks, 10865))
			}
		} else {
			enabledSystemProxy = true
			fmt.Println("GNOME system proxy: enabled (will be restored on exit)")
			defer func() {
				if err := efan.DisableGNOMEProxy(paths); err != nil && !errors.Is(err, efan.ErrNoGsettings) {
					fmt.Fprintf(os.Stderr, "warning: could not restore the GNOME proxy: %v\n", err)
				}
			}()
		}
	} else if !*daemonMode {
		fmt.Println("Terminal apps can use:")
		efan.PrintProxyEnv(os.Stdout, portOf(actualHTTP, 10866), portOf(actualSocks, 10865))
	}
	settings.SystemProxy = enabledSystemProxy
	_ = efan.SaveSettings(paths.Settings, settings)

	if *daemonMode {
		state := efan.DaemonState{
			PID:         os.Getpid(),
			Node:        node.Name,
			Socks:       actualSocks,
			HTTP:        actualHTTP,
			SystemProxy: enabledSystemProxy,
			Debug:       *debug,
			StartedAt:   time.Now(),
		}
		if err := efan.SaveDaemonState(paths.Daemon, state); err != nil {
			return fmt.Errorf("save daemon state: %w", err)
		}
		if err := efan.SavePID(paths.PID, os.Getpid()); err != nil {
			_ = efan.RemoveDaemonState(paths.Daemon)
			return fmt.Errorf("save daemon pid: %w", err)
		}
		defer func() {
			_ = efan.RemoveDaemonState(paths.Daemon)
			_ = os.Remove(paths.PID)
		}()
		fmt.Println("Daemon ready.")
	} else {
		fmt.Println("Press Ctrl-C to stop.")
	}
	fmt.Println()

	select {
	case <-ctx.Done():
		fmt.Println("Stopping...")
	case err := <-errCh:
		if err != nil {
			return err
		}
	}
	return nil
}

type nodeTestResult struct {
	Index   int
	Name    string
	Server  string
	Port    int
	Latency time.Duration
	Err     error
}

func cmdTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	nodeFlag := fs.String("node", "", "test one node by name or 1-based index")
	filter := fs.String("filter", "", "only test node names containing this text")
	limit := fs.Int("limit", 0, "test at most N nodes (0 = all)")
	concurrency := fs.Int("concurrency", 6, "number of parallel probes")
	timeout := fs.Duration("timeout", 8*time.Second, "timeout per probe")
	retries := fs.Int("retries", 1, "additional attempts after a failed probe")
	target := fs.String("target", "example.com:80", "TCP target used to verify egress")
	asJSON := fs.Bool("json", false, "print JSON results")
	save := fs.Bool("save", false, "set the fastest working node as default")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *concurrency < 1 {
		return errors.New("--concurrency must be at least 1")
	}
	if *concurrency > 32 {
		*concurrency = 32
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	if *retries < 0 {
		return errors.New("--retries cannot be negative")
	}
	targetHost, targetPort, err := parseProbeTarget(*target)
	if err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	settings, err := efan.LoadSettings(paths.Settings)
	if err != nil {
		return err
	}
	cfg, err := x365.LoadConfig(paths.Config)
	if err != nil {
		return fmt.Errorf("load %s: %w (run 'efan login' first)", paths.Config, err)
	}
	nodes := cfg.Nodes
	if strings.TrimSpace(*nodeFlag) != "" {
		n, err := selectNode(cfg, *nodeFlag, false, "")
		if err != nil {
			return err
		}
		nodes = []x365.Node{n}
	} else if strings.TrimSpace(*filter) != "" {
		needle := strings.ToLower(strings.TrimSpace(*filter))
		filtered := make([]x365.Node, 0, len(nodes))
		for _, n := range nodes {
			if strings.Contains(strings.ToLower(n.Name), needle) {
				filtered = append(filtered, n)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("no nodes match %q", *filter)
		}
		nodes = filtered
	}
	if *limit > 0 && len(nodes) > *limit {
		nodes = nodes[:*limit]
	}
	if len(nodes) == 0 {
		return errors.New("no nodes to test")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	type job struct {
		index       int
		node        x365.Node
		material    []byte
		materialErr error
	}
	jobs := make(chan job)
	outcomes := make(chan nodeTestResult)
	var workers sync.WaitGroup
	workerCount := *concurrency
	if workerCount > len(nodes) {
		workerCount = len(nodes)
	}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				res := nodeTestResult{Index: j.index, Name: j.node.Name, Server: j.node.Server, Port: j.node.Port}
				if j.materialErr != nil {
					res.Err = j.materialErr
					outcomes <- res
					continue
				}
				attempts := *retries + 1
				for attempt := 0; attempt < attempts; attempt++ {
					latency, probeErr := x365.ProbeNode(ctx, j.node, j.material, targetHost, targetPort, *timeout)
					if probeErr == nil {
						res.Latency = latency
						res.Err = nil
						break
					}
					res.Err = probeErr
					if attempt+1 < attempts {
						select {
						case <-time.After(250 * time.Millisecond):
						case <-ctx.Done():
						}
					}
				}
				outcomes <- res
			}
		}()
	}
	go func() {
		defer func() {
			close(jobs)
			workers.Wait()
			close(outcomes)
		}()
		for i, n := range nodes {
			material, materialErr := x365.MaterialFromUUID(n.UserID)
			select {
			case jobs <- job{index: i + 1, node: n, material: material, materialErr: materialErr}:
			case <-ctx.Done():
				return
			}
		}
	}()

	if !*asJSON {
		fmt.Fprintf(os.Stderr, "Testing %d node(s) against %s with %d worker(s)...\n", len(nodes), *target, workerCount)
	}
	results := make([]nodeTestResult, 0, len(nodes))
	for res := range outcomes {
		results = append(results, res)
		if !*asJSON {
			if res.Err != nil {
				fmt.Fprintf(os.Stderr, "FAIL  #%-3d %-28s %s\n", res.Index, res.Name, shortProbeError(res.Err))
			} else {
				fmt.Fprintf(os.Stderr, "OK    #%-3d %-28s %s\n", res.Index, res.Name, res.Latency.Round(time.Millisecond))
			}
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		if (results[i].Err == nil) != (results[j].Err == nil) {
			return results[i].Err == nil
		}
		if results[i].Err == nil && results[i].Latency != results[j].Latency {
			return results[i].Latency < results[j].Latency
		}
		return results[i].Index < results[j].Index
	})

	var working, failed []nodeTestResult
	for _, res := range results {
		if res.Err == nil {
			working = append(working, res)
		} else {
			failed = append(failed, res)
		}
	}

	if *asJSON {
		type jsonResult struct {
			Index     int    `json:"index"`
			Name      string `json:"name"`
			Server    string `json:"server"`
			Port      int    `json:"port"`
			OK        bool   `json:"ok"`
			LatencyMS int64  `json:"latency_ms,omitempty"`
			Error     string `json:"error,omitempty"`
		}
		out := make([]jsonResult, 0, len(results))
		for _, res := range results {
			item := jsonResult{
				Index:  res.Index,
				Name:   res.Name,
				Server: res.Server,
				Port:   res.Port,
				OK:     res.Err == nil,
			}
			if res.Err == nil {
				item.LatencyMS = res.Latency.Milliseconds()
			} else {
				item.Error = shortProbeError(res.Err)
			}
			out = append(out, item)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
	} else {
		fmt.Printf("\nWorking nodes: %d/%d\n", len(working), len(results))
		if len(working) > 1 {
			fmt.Println("Sorted by latency; IDX is the position within this test.")
		}
		if len(working) > 0 {
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "IDX\tNODE\tSERVER\tLATENCY")
			for _, res := range working {
				fmt.Fprintf(tw, "%d\t%s\t%s:%d\t%s\n", res.Index, res.Name, res.Server, res.Port, res.Latency.Round(time.Millisecond))
			}
			tw.Flush()
			best := working[0]
			fmt.Printf("\nFastest: %s (%s)\n", best.Name, best.Latency.Round(time.Millisecond))
			if *save {
				settings.SelectedNode = best.Name
				if err := efan.SaveSettings(paths.Settings, settings); err != nil {
					return err
				}
				fmt.Printf("Saved %q as the default node.\n", best.Name)
			}
			printTestNextStep(paths, settings, best, *filter, strings.TrimSpace(*nodeFlag) == "", *save)
		}
		if len(failed) > 0 {
			fmt.Printf("\nFailed nodes: %d\n", len(failed))
			for _, res := range failed {
				fmt.Printf("  #%-4d %-28s %s\n", res.Index, res.Name, shortProbeError(res.Err))
			}
		}
	}

	if len(working) == 0 {
		return fmt.Errorf("no working nodes among %d tested", len(results))
	}
	return nil
}

func printTestNextStep(paths efan.Paths, settings efan.Settings, best nodeTestResult, filter string, indexHint, saved bool) {
	state, err := runningDaemon(paths)
	if err != nil {
		fmt.Printf("Daemon:  state error: %v\n", err)
		return
	}
	defaultNode := settings.SelectedNode
	if defaultNode == "" {
		defaultNode = "(not set)"
	}
	fmt.Printf("Default: %s\n", defaultNode)
	if state == nil {
		fmt.Println("Daemon:  stopped")
		if saved {
			fmt.Println("Next:    efan start")
		} else {
			fmt.Printf("Next:    efan start --node %q\n", best.Name)
		}
		return
	}
	fmt.Printf("Daemon:  %s (running)\n", state.Node)
	if state.Node == best.Name {
		fmt.Println("Next:    none; the daemon is already using the fastest node.")
		return
	}
	fmt.Printf("Next:    efan node use %q\n", best.Name)
	if indexHint {
		if filter != "" {
			fmt.Printf("Or:      efan node use %d --filter %q\n", best.Index, filter)
		} else {
			fmt.Printf("Or:      efan node use %d\n", best.Index)
		}
	}
	fmt.Println("         (efan test does not change the current node)")
}

func parseProbeTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, errors.New("--target cannot be empty")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portText = "80"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid target port %q", portText)
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, errors.New("--target host cannot be empty")
	}
	return host, port, nil
}

func shortProbeError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.Join(strings.Fields(err.Error()), " ")
	if len(text) > 180 {
		text = text[:180] + "..."
	}
	return text
}

func cmdProxy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: efan proxy on|off|status|env")
	}
	switch args[0] {
	case "on":
		fs := flag.NewFlagSet("proxy on", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		httpPort := fs.Int("http-port", 10866, "HTTP proxy port")
		socksPort := fs.Int("socks-port", 10865, "SOCKS5 proxy port")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		paths, err := efan.DefaultPaths()
		if err != nil {
			return err
		}
		applyDefaultProxyPorts(paths, fs, httpPort, socksPort)
		warnIfNotListening(*socksPort, *httpPort)
		if err := efan.EnableGNOMEProxy(paths, *httpPort, *socksPort); err != nil {
			if errors.Is(err, efan.ErrNoGsettings) {
				fmt.Fprintln(os.Stderr, "GNOME proxy settings are unavailable; use these environment variables:")
				efan.PrintProxyEnv(os.Stdout, *httpPort, *socksPort)
				return nil
			}
			return err
		}
		if err := updateDaemonSystemProxy(paths, true); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not update daemon state: %v\n", err)
		}
		fmt.Printf("GNOME system proxy enabled: HTTP 127.0.0.1:%d, SOCKS 127.0.0.1:%d\n", *httpPort, *socksPort)
		return nil
	case "off":
		paths, err := efan.DefaultPaths()
		if err != nil {
			return err
		}
		if err := efan.DisableGNOMEProxy(paths); err != nil {
			if errors.Is(err, efan.ErrNoGsettings) {
				fmt.Fprintln(os.Stderr, "GNOME proxy settings are unavailable; unset the proxy environment variables in your shell.")
				return nil
			}
			return err
		}
		if err := updateDaemonSystemProxy(paths, false); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not update daemon state: %v\n", err)
		}
		fmt.Println("GNOME system proxy restored.")
		return nil
	case "status":
		paths, err := efan.DefaultPaths()
		if err != nil {
			return err
		}
		fmt.Printf("GNOME proxy mode: %s\n", efan.GNOMEProxyMode())
		if state, err := runningDaemon(paths); err == nil && state != nil {
			httpPort, socksPort := daemonPorts(state)
			fmt.Printf("Daemon:          pid %d, HTTP %d, SOCKS %d\n", state.PID, httpPort, socksPort)
		}
		return nil
	case "env":
		fs := flag.NewFlagSet("proxy env", flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		httpPort := fs.Int("http-port", 10866, "HTTP proxy port")
		socksPort := fs.Int("socks-port", 10865, "SOCKS5 proxy port")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		paths, err := efan.DefaultPaths()
		if err != nil {
			return err
		}
		applyDefaultProxyPorts(paths, fs, httpPort, socksPort)
		efan.PrintProxyEnv(os.Stdout, *httpPort, *socksPort)
		return nil
	default:
		return fmt.Errorf("unknown proxy action %q", args[0])
	}
}

func updateDaemonSystemProxy(paths efan.Paths, enabled bool) error {
	state, err := runningDaemon(paths)
	if err != nil {
		return err
	}
	if state == nil || state.SystemProxy == enabled {
		return nil
	}
	state.SystemProxy = enabled
	return efan.SaveDaemonState(paths.Daemon, *state)
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	settings, _ := efan.LoadSettings(paths.Settings)
	state, stateErr := runningDaemon(paths)

	fmt.Println("Efan Native")
	if stateErr != nil {
		fmt.Printf("  Daemon:     state error: %v\n", stateErr)
	} else if state == nil {
		fmt.Println("  Daemon:     stopped")
	} else {
		uptime := ""
		if !state.StartedAt.IsZero() {
			uptime = ", up " + time.Since(state.StartedAt).Round(time.Second).String()
		}
		fmt.Printf("  Daemon:     running (pid %d%s)\n", state.PID, uptime)
		if state.Node != "" {
			fmt.Printf("  Node:       %s\n", state.Node)
		}
		if state.Socks != "" {
			fmt.Printf("  SOCKS5:     %s\n", state.Socks)
		}
		if state.HTTP != "" {
			fmt.Printf("  HTTP:       %s\n", state.HTTP)
		} else {
			fmt.Println("  HTTP:       disabled")
		}
	}

	httpPort, socksPort := daemonPorts(state)
	if state == nil {
		httpPort = portOf(settings.HTTPListen, 10866)
		socksPort = portOf(settings.Listen, 10865)
	}
	fmt.Printf("  Terminal:   %s\n", terminalProxyState(httpPort, socksPort))
	if state == nil {
		socksAddr := settings.Listen
		if socksAddr == "" {
			socksAddr = defaultSocksAddr
		}
		httpAddr := settings.HTTPListen
		if httpAddr == "" {
			httpAddr = defaultHTTPAddr
		}
		if tcpReachable(socksAddr, 250*time.Millisecond) || tcpReachable(httpAddr, 250*time.Millisecond) {
			fmt.Println("  Foreground: proxy ports are listening (not managed; stop that 'efan connect' first)")
		}
	}
	gnome := efan.GNOMEProxyMode()
	if state != nil {
		if state.SystemProxy {
			gnome += " (daemon-managed)"
		} else {
			gnome += " (not managed by efan; run 'efan on' for browsers)"
		}
	}
	fmt.Printf("  GNOME:      %s\n", gnome)

	if cfg, err := x365.LoadConfig(paths.Config); err == nil {
		fmt.Printf("  Config:     %d node(s) in %s\n", len(cfg.Nodes), paths.Config)
		if settings.SelectedNode != "" {
			fmt.Printf("  Selected:   %s\n", settings.SelectedNode)
		}
	} else {
		fmt.Println("  Config:     no local node list (run 'efan login')")
	}
	if session, err := efan.LoadSession(paths.Session); err == nil {
		fmt.Printf("  Session:    %s\n", session.Email)
		if session.ExpiresAt > 0 {
			fmt.Printf("  Token:      expires %s\n", time.Unix(session.ExpiresAt, 0).Format(time.RFC3339))
		} else {
			fmt.Println("  Token:      expiry unknown")
		}
		printServicesIndent(session.Services, "  ")
	} else {
		fmt.Println("  Session:    not logged in")
	}
	if state != nil || fileExists(paths.Log) {
		fmt.Printf("  Log:        %s\n", paths.Log)
	}
	return nil
}

func terminalProxyState(httpPort, socksPort int) string {
	all := strings.ToLower(os.Getenv("all_proxy") + " " + os.Getenv("ALL_PROXY"))
	http := strings.ToLower(os.Getenv("http_proxy") + " " + os.Getenv("HTTP_PROXY"))
	if strings.Contains(all, fmt.Sprintf("127.0.0.1:%d", socksPort)) ||
		strings.Contains(http, fmt.Sprintf("127.0.0.1:%d", httpPort)) {
		return "on"
	}
	for _, name := range []string{"http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"} {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return "other proxy"
		}
	}
	return "off"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func cmdWhmcs(args []string) error {
	fs := flag.NewFlagSet("whmcs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	apiBase := fs.String("api-base", envOr("EFAN_API_BASE", efan.DefaultAPIBase), "API base URL")
	appVersion := fs.String("app-version", envOr("EFAN_APP_VERSION", efan.DefaultAppVersion), "app version reported to the API")
	debug := fs.Bool("debug", false, "verbose diagnostics")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, _, paths, err := loadClient(*apiBase, *appVersion, *debug, false)
	if err != nil {
		return err
	}
	session, err := loadSession(paths)
	if err != nil {
		return err
	}
	if session.SessionToken == "" && session.Cookie == "" {
		return errors.New("no session token stored; run 'efan login' again")
	}
	if sessionNeedsCookie(session) {
		return errors.New("stored session has no API cookie (created by an older efan); run 'efan login' once")
	}
	if err := applySessionCookie(client, &session); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// The WHMCS endpoint accepts the server-session token in the body; the
	// HttpOnly cookie is sent as well. If an older session only has a cookie,
	// retry with the cookie alone.
	url, _, err := client.SSOLogin(ctx, session.SessionToken)
	if err != nil && efan.IsAuthError(err) && session.Cookie != "" && session.SessionToken != "" {
		url, _, err = client.SSOLogin(ctx, "")
	}
	if err != nil {
		return err
	}
	captureSessionCookie(client, &session)
	if saveErr := efan.SaveSession(paths.Session, session); saveErr != nil {
		return saveErr
	}
	fmt.Println("Open this one-time WHMCS login URL in a browser:")
	fmt.Println(url)
	fmt.Println()
	fmt.Println("If you need the official Clash subscription instead of this native")
	fmt.Println("client, run 'efan clash' to print the direct subscription URL.")
	return nil
}

func cmdLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	all := fs.Bool("all", false, "also remove the local RSA key and settings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	if err := efan.ClearSession(paths.Session); err != nil {
		return err
	}
	_ = os.Remove(paths.Config)
	_ = os.Remove(paths.Plaintext)
	if err := efan.DisableGNOMEProxy(paths); err != nil && !errors.Is(err, efan.ErrNoGsettings) {
		fmt.Fprintf(os.Stderr, "warning: could not restore the GNOME proxy: %v\n", err)
	}
	if *all {
		_ = os.Remove(paths.Key)
		_ = os.Remove(paths.Settings)
		_ = os.Remove(paths.Device)
	}
	fmt.Println("Logged out; local session and node config removed.")
	return nil
}

func cmdExtractKey(args []string) error {
	fs := flag.NewFlagSet("extract-key", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dll := fs.String("dll", "", "path to client.dll")
	out := fs.String("out", "", "output PEM path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	dllPath := efan.FindClientDLL(*dll)
	if dllPath == "" {
		return errors.New("client.dll not found; pass --dll /path/to/client.dll")
	}
	pemBytes, err := efan.ExtractKeyFromDLL(dllPath)
	if err != nil {
		return err
	}
	outPath := *out
	if outPath == "" {
		outPath = paths.Key
	}
	if err := efan.SaveKey(outPath, pemBytes); err != nil {
		return err
	}
	key, err := efan.ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s (key fingerprint %s)\n", outPath, efan.KeyFingerprint(key))
	return nil
}

func loadSession(paths efan.Paths) (efan.Session, error) {
	session, err := efan.LoadSession(paths.Session)
	if err != nil {
		if os.IsNotExist(err) {
			return efan.Session{}, errors.New("not logged in; run 'efan login'")
		}
		return efan.Session{}, err
	}
	return session, nil
}

func mergeSession(dst, src *efan.Session) {
	if src.Email != "" {
		dst.Email = src.Email
	}
	if src.AccessToken != "" {
		dst.AccessToken = src.AccessToken
	}
	if src.SessionToken != "" {
		dst.SessionToken = src.SessionToken
	}
	if src.Cookie != "" {
		dst.Cookie = src.Cookie
	}
	if src.ExpiresAt > 0 {
		dst.ExpiresAt = src.ExpiresAt
	}
	if len(src.Services) > 0 {
		dst.Services = src.Services
	}
}

func applySessionCookie(client *efan.APIClient, session *efan.Session) error {
	if session.Cookie == "" {
		return nil
	}
	if err := client.SetCookieHeader(session.Cookie); err != nil {
		return fmt.Errorf("restore API session cookie: %w", err)
	}
	return nil
}

func sessionNeedsCookie(session efan.Session) bool {
	return session.Cookie == "" && session.SessionToken != "" && session.SessionToken == session.AccessToken
}

func captureSessionCookie(client *efan.APIClient, session *efan.Session) {
	oldToken := sessionCookieValue(session.Cookie)
	cookie := client.CookieHeader()
	if cookie == "" {
		return
	}
	session.Cookie = cookie
	newToken := sessionCookieValue(cookie)
	if newToken != "" && (session.SessionToken == "" || session.SessionToken == oldToken) {
		// Login responses on some builds have no body session_token, and a
		// rotated cookie must also update the refresh/SSO token.
		session.SessionToken = newToken
	}
}

func sessionCookieValue(header string) string {
	var first string
	for _, part := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if first == "" {
			first = value
		}
		if strings.HasPrefix(name, "server_session_") {
			return value
		}
	}
	return first
}

func printSession(session efan.Session) {
	fmt.Printf("Logged in as %s\n", session.Email)
	if session.ExpiresAt > 0 {
		fmt.Printf("Token expires: %s\n", time.Unix(session.ExpiresAt, 0).Format(time.RFC3339))
	}
	printServices(session.Services)
}

func printServices(services []efan.Service) {
	printServicesIndent(services, "")
}

func printServicesIndent(services []efan.Service, indent string) {
	if len(services) == 0 {
		fmt.Printf("%sServices: none reported\n", indent)
		return
	}
	fmt.Printf("%sServices:\n", indent)
	for _, svc := range services {
		name := svc.Name
		if name == "" {
			name = svc.ServiceID
		}
		if name == "" {
			name = "(unnamed)"
		}
		details := make([]string, 0, 3)
		if svc.ExpiresAt != "" {
			details = append(details, "expires "+svc.ExpiresAt)
		}
		if svc.Traffic != "" {
			details = append(details, "traffic "+svc.Traffic)
		}
		if len(details) > 0 {
			fmt.Printf("%s  - %s (%s)\n", indent, name, strings.Join(details, ", "))
		} else {
			fmt.Printf("%s  - %s\n", indent, name)
		}
	}
}

func selectNode(cfg x365.Config, query string, fallback bool, remembered string) (x365.Node, error) {
	if len(cfg.Nodes) == 0 {
		return x365.Node{}, errors.New("config contains no nodes")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		query = strings.TrimSpace(remembered)
	}
	if query == "" {
		return cfg.Nodes[0], nil
	}
	if index, err := strconv.Atoi(query); err == nil && index >= 1 && index <= len(cfg.Nodes) {
		return cfg.Nodes[index-1], nil
	}
	lower := strings.ToLower(query)
	var matches []x365.Node
	for _, node := range cfg.Nodes {
		nodeLower := strings.ToLower(node.Name)
		if nodeLower == lower {
			return node, nil
		}
		if strings.Contains(nodeLower, lower) {
			matches = append(matches, node)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, node := range matches {
			names = append(names, node.Name)
		}
		return x365.Node{}, fmt.Errorf("node %q is ambiguous: %s", query, strings.Join(names, ", "))
	}
	if fallback {
		fmt.Fprintf(os.Stderr, "warning: remembered node %q not found; using %q\n", query, cfg.Nodes[0].Name)
		return cfg.Nodes[0], nil
	}
	return x365.Node{}, fmt.Errorf("node %q not found; run 'efan list'", query)
}

func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(data), err
	}
	return promptLine("Password: ")
}

func friendlyError(err error) error {
	var apiErr *efan.APIError
	if errors.As(err, &apiErr) {
		if strings.Contains(apiErr.Message, "服务不存在或无权访问") {
			return fmt.Errorf("%s (no active service, or the subscription has expired)", apiErr.Message)
		}
	}
	return err
}

func isSignatureError(err error) bool {
	var apiErr *efan.APIError
	if errors.As(err, &apiErr) {
		message := apiErr.Message
		return strings.Contains(message, "签名") || strings.Contains(strings.ToLower(message), "sign")
	}
	return false
}

func portOf(addr string, fallback int) int {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return fallback
	}
	return port
}

func applyDefaultProxyPorts(paths efan.Paths, fs *flag.FlagSet, httpPort, socksPort *int) {
	httpSet := wasFlagSet(fs, "http-port")
	socksSet := wasFlagSet(fs, "socks-port")
	if httpSet && socksSet {
		return
	}
	if state, err := runningDaemon(paths); err == nil && state != nil {
		dhttp, dsocks := daemonPorts(state)
		if !httpSet {
			*httpPort = dhttp
		}
		if !socksSet {
			*socksPort = dsocks
		}
		return
	}
	settings, _ := efan.LoadSettings(paths.Settings)
	if !httpSet {
		*httpPort = portOf(settings.HTTPListen, *httpPort)
	}
	if !socksSet {
		*socksPort = portOf(settings.Listen, *socksPort)
	}
}

func warnIfNotListening(ports ...int) {
	for _, port := range ports {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, 400*time.Millisecond)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: nothing is listening on %s; start 'efan start' or 'efan connect' first\n", address)
			continue
		}
		_ = conn.Close()
	}
}
