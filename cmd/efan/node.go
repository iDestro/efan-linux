package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"efan-linux/internal/efan"
	"efan-linux/internal/x365"
)

type nodeCommandOptions struct {
	filter    string
	noRestart bool
	noTest    bool
}

func cmdNode(args []string) error {
	if len(args) == 0 {
		return nodeInteractive(nodeCommandOptions{})
	}
	switch args[0] {
	case "ls", "list":
		return nodeList(args[1:])
	case "use", "switch":
		return nodeUse(args[1:])
	default:
		if strings.HasPrefix(args[0], "-") {
			return nodeInteractiveArgs(args)
		}
		return nodeUse(args)
	}
}

func registerNodeFlags(fs *flag.FlagSet, opts *nodeCommandOptions) {
	fs.StringVar(&opts.filter, "filter", "", "only show node names containing this text")
	fs.BoolVar(&opts.noRestart, "no-restart", false, "only save the default node; do not restart a running daemon")
	fs.BoolVar(&opts.noTest, "no-test", false, "skip the reachability check before restarting")
}

func nodeInteractiveArgs(args []string) error {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts nodeCommandOptions
	registerNodeFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q; use 'efan node use NAME'", fs.Arg(0))
	}
	return nodeInteractive(opts)
}

func nodeList(args []string) error {
	fs := flag.NewFlagSet("node ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts nodeCommandOptions
	registerNodeFlags(fs, &opts)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
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
	nodes := filterNodes(cfg.Nodes, opts.filter)
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes match %q", opts.filter)
	}
	printNodeList(nodes, settings.SelectedNode, opts.filter)
	return nil
}

func nodeUse(args []string) error {
	opts, query, err := parseNodeUseArgs(args)
	if err != nil {
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
	settings, err := efan.LoadSettings(paths.Settings)
	if err != nil {
		return err
	}
	nodes := filterNodes(cfg.Nodes, opts.filter)
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes match %q", opts.filter)
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return nodeInteractiveWith(paths, nodes, settings, opts)
	}
	node, err := selectNode(x365.Config{Nodes: nodes}, query, false, "")
	if err != nil {
		return err
	}
	return applyNode(paths, settings, node, opts)
}

func parseNodeUseArgs(args []string) (nodeCommandOptions, string, error) {
	var opts nodeCommandOptions
	var words []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			fmt.Fprintln(os.Stderr, "usage: efan node use [NAME|INDEX] [--filter TEXT] [--no-restart] [--no-test]")
			return opts, "", flag.ErrHelp
		case arg == "--no-restart":
			opts.noRestart = true
		case arg == "--no-test":
			opts.noTest = true
		case arg == "--filter":
			if i+1 >= len(args) {
				return opts, "", errors.New("--filter needs a value")
			}
			i++
			opts.filter = args[i]
		case strings.HasPrefix(arg, "--filter="):
			opts.filter = strings.TrimPrefix(arg, "--filter=")
		case strings.HasPrefix(arg, "-"):
			return opts, "", fmt.Errorf("unknown option %q", arg)
		default:
			words = append(words, arg)
		}
	}
	return opts, strings.Join(words, " "), nil
}

func nodeInteractive(opts nodeCommandOptions) error {
	paths, err := efan.DefaultPaths()
	if err != nil {
		return err
	}
	cfg, err := x365.LoadConfig(paths.Config)
	if err != nil {
		return fmt.Errorf("load %s: %w (run 'efan login' first)", paths.Config, err)
	}
	settings, err := efan.LoadSettings(paths.Settings)
	if err != nil {
		return err
	}
	nodes := filterNodes(cfg.Nodes, opts.filter)
	if len(nodes) == 0 {
		return fmt.Errorf("no nodes match %q", opts.filter)
	}
	return nodeInteractiveWith(paths, nodes, settings, opts)
}

func nodeInteractiveWith(paths efan.Paths, nodes []x365.Node, settings efan.Settings, opts nodeCommandOptions) error {
	node, canceled, err := pickNode(nodes, settings.SelectedNode, opts.filter)
	if err != nil {
		return err
	}
	if canceled {
		return nil
	}
	return applyNode(paths, settings, node, opts)
}

func filterNodes(nodes []x365.Node, filter string) []x365.Node {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return nodes
	}
	out := make([]x365.Node, 0, len(nodes))
	for _, node := range nodes {
		if strings.Contains(strings.ToLower(node.Name), filter) {
			out = append(out, node)
		}
	}
	return out
}

func printNodeList(nodes []x365.Node, selected, filter string) {
	header := fmt.Sprintf("Nodes (%d)", len(nodes))
	if filter != "" {
		header += fmt.Sprintf(" matching %q", filter)
	}
	fmt.Println(header)
	for i, node := range nodes {
		marker := " "
		if node.Name == selected {
			marker = "*"
		}
		fmt.Printf("%s %3d. %-28s %s:%d\n", marker, i+1, node.Name, node.Server, node.Port)
	}
}

func pickNode(nodes []x365.Node, selected, filter string) (x365.Node, bool, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		if _, err := exec.LookPath("fzf"); err == nil {
			if node, canceled, err := pickNodeFzf(nodes); err == nil {
				return node, canceled, nil
			}
		}
	}
	printNodeList(nodes, selected, filter)
	answer, err := promptLine("Select node (number or name, q to cancel): ")
	if err != nil {
		return x365.Node{}, false, err
	}
	answer = strings.TrimSpace(answer)
	if answer == "" || strings.EqualFold(answer, "q") || strings.EqualFold(answer, "quit") {
		return x365.Node{}, true, nil
	}
	if index, err := strconv.Atoi(answer); err == nil {
		if index < 1 || index > len(nodes) {
			return x365.Node{}, false, fmt.Errorf("selection %d is out of range", index)
		}
		return nodes[index-1], false, nil
	}
	node, err := selectNode(x365.Config{Nodes: nodes}, answer, false, "")
	if err != nil {
		return x365.Node{}, false, err
	}
	return node, false, nil
}

func pickNodeFzf(nodes []x365.Node) (x365.Node, bool, error) {
	var input strings.Builder
	for i, node := range nodes {
		fmt.Fprintf(&input, "%d\t%s\t%s:%d\n", i+1, node.Name, node.Server, node.Port)
	}
	cmd := exec.Command("fzf", "--height=80%", "--reverse", "--prompt=Node > ", "--delimiter=\t", "--with-nth=2..")
	cmd.Stdin = strings.NewReader(input.String())
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 130 {
			return x365.Node{}, true, nil
		}
		return x365.Node{}, false, err
	}
	field := strings.SplitN(strings.TrimSpace(string(out)), "\t", 2)[0]
	index, err := strconv.Atoi(field)
	if err != nil || index < 1 || index > len(nodes) {
		return x365.Node{}, false, fmt.Errorf("unexpected fzf selection %q", strings.TrimSpace(string(out)))
	}
	return nodes[index-1], false, nil
}

func applyNode(paths efan.Paths, settings efan.Settings, node x365.Node, opts nodeCommandOptions) error {
	settings.SelectedNode = node.Name
	if err := efan.SaveSettings(paths.Settings, settings); err != nil {
		return err
	}
	fmt.Printf("Selected node: %s (%s:%d)\n", node.Name, node.Server, node.Port)

	state, err := runningDaemon(paths)
	if err != nil {
		return err
	}
	if state == nil {
		fmt.Println("Start the tunnel with 'efan start' or 'efan on'.")
		return nil
	}
	if state.Node == node.Name {
		fmt.Printf("Daemon is already using %s.\n", node.Name)
		return nil
	}
	if opts.noRestart {
		fmt.Printf("Daemon is still on %s; run 'efan restart' to apply.\n", state.Node)
		return nil
	}
	if !opts.noTest {
		material, err := x365.MaterialFromUUID(node.UserID)
		if err != nil {
			return fmt.Errorf("node %q has an invalid UUID: %w", node.Name, err)
		}
		fmt.Fprintf(os.Stderr, "Checking %s before switching... ", node.Name)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		latency, probeErr := x365.ProbeNode(ctx, node, material, "example.com", 80, 8*time.Second)
		cancel()
		if probeErr != nil {
			return fmt.Errorf("node %q is not reachable: %v (daemon left on %s)", node.Name, probeErr, state.Node)
		}
		fmt.Fprintf(os.Stderr, "OK (%s)\n", latency.Round(time.Millisecond))
	}

	startOpts := startOptionsFromState(state)
	startOpts.Node = node.Name
	if _, err := stopDaemon(paths, false); err != nil {
		return err
	}
	started, err := spawnDaemon(paths, startOpts)
	if err != nil {
		return fmt.Errorf("daemon stopped, but the new one failed to start: %w", err)
	}
	fmt.Printf("Daemon restarted on %s (pid %d).\n", started.Node, started.PID)
	return nil
}

func startOptionsFromState(state *efan.DaemonState) startOptions {
	return startOptions{
		Node:        state.Node,
		Listen:      state.Socks,
		HTTPListen:  state.HTTP,
		NoHTTP:      state.HTTP == "",
		SystemProxy: state.SystemProxy,
		Debug:       state.Debug,
	}
}
