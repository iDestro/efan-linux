package x365

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

type Node struct {
	Name      string
	UserID    string
	Server    string
	Port      int
	Path      string
	Host      string
	SNI       string
	PublicKey string
	ShortID   string

	fingerprint             string
	shadowsocksSniffConfigs []shadowsocksSniffConfig
}

type Config struct {
	Listen  string
	LogPath string
	Nodes   []Node
}

type shadowsocksSniffConfig struct {
	Name     string `yaml:"name"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Method   string `yaml:"method"`
	Cipher   string `yaml:"cipher"`
	Password string `yaml:"password"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	config, err := parseConfigText(string(data))
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return config, nil
}

func parseNodesText(text string) ([]Node, error) {
	config, err := parseConfigText(text)
	if err != nil {
		return nil, err
	}
	return config.Nodes, nil
}

func parseConfigText(text string) (Config, error) {
	var config struct {
		Listen      string        `yaml:"listen"`
		LogPath     string        `yaml:"log_path"`
		Proxies     yaml.MapSlice `yaml:"proxies"`
		ProxiesTmpl string        `yaml:"proxies_tmpl"`
		ProxiesUUID string        `yaml:"proxies_uuid"`
		Sniff       struct {
			Shadowsocks []shadowsocksSniffConfig `yaml:"shadowsocks"`
		} `yaml:"sniff"`
	}
	if err := yaml.Unmarshal([]byte(text), &config); err != nil {
		return Config{}, fmt.Errorf("parse YAML: %w", err)
	}
	sniffConfigs, err := normalizeShadowsocksSniffConfigs(config.Sniff.Shadowsocks)
	if err != nil {
		return Config{}, err
	}
	if len(config.Proxies) == 0 {
		proxies, err := proxiesFromTemplate(config.ProxiesTmpl, config.ProxiesUUID)
		if err != nil {
			return Config{}, err
		}
		config.Proxies = proxies
	}

	var nodes []Node
	for _, item := range config.Proxies {
		name := fmt.Sprint(item.Key)
		uris, err := proxyURIs(item.Value)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", name, err)
		}
		for idx, rawURI := range uris {
			nodeName := name
			if len(uris) > 1 {
				nodeName = fmt.Sprintf("%s #%d", name, idx+1)
			}
			node, err := parseNode(nodeName, rawURI)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", nodeName, err)
			}
			node.shadowsocksSniffConfigs = sniffConfigs
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return Config{}, errors.New("proxies field contains no x365 nodes")
	}
	sortNodes(nodes)
	logPath := strings.TrimSpace(config.LogPath)
	return Config{
		Listen:  strings.TrimSpace(config.Listen),
		LogPath: logPath,
		Nodes:   nodes,
	}, nil
}

func proxiesFromTemplate(encoded, uuid string) (yaml.MapSlice, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("missing or empty proxies field")
	}
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return nil, errors.New("missing proxies_uuid for proxies_tmpl")
	}
	if _, err := MaterialFromUUID(uuid); err != nil {
		return nil, fmt.Errorf("invalid proxies_uuid: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode proxies_tmpl: %w", err)
	}
	var tmpl yaml.MapSlice
	if err := yaml.Unmarshal(decoded, &tmpl); err != nil {
		return nil, fmt.Errorf("parse proxies_tmpl YAML: %w", err)
	}
	if len(tmpl) == 0 {
		return nil, errors.New("proxies_tmpl contains no proxy groups")
	}

	proxies := make(yaml.MapSlice, 0, len(tmpl))
	for _, item := range tmpl {
		uris, err := proxyTemplateURIs(item.Value, uuid)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fmt.Sprint(item.Key), err)
		}
		proxies = append(proxies, yaml.MapItem{Key: item.Key, Value: uris})
	}
	return proxies, nil
}

func normalizeShadowsocksSniffConfigs(configs []shadowsocksSniffConfig) ([]shadowsocksSniffConfig, error) {
	if len(configs) == 0 {
		return nil, nil
	}
	normalized := make([]shadowsocksSniffConfig, 0, len(configs))
	for i, config := range configs {
		config.Name = strings.TrimSpace(config.Name)
		config.Server = strings.TrimSpace(config.Server)
		config.Method = strings.TrimSpace(config.Method)
		config.Cipher = strings.TrimSpace(config.Cipher)
		if config.Method == "" {
			config.Method = config.Cipher
		}
		config.Method = strings.ToLower(config.Method)
		config.Cipher = ""
		if config.Server == "" {
			return nil, fmt.Errorf("sniff.shadowsocks[%d]: missing server", i)
		}
		if config.Port <= 0 || config.Port > 65535 {
			return nil, fmt.Errorf("sniff.shadowsocks[%d]: invalid port", i)
		}
		if config.Method == "" {
			return nil, fmt.Errorf("sniff.shadowsocks[%d]: missing method", i)
		}
		if config.Password == "" {
			return nil, fmt.Errorf("sniff.shadowsocks[%d]: missing password", i)
		}
		normalized = append(normalized, config)
	}
	return normalized, nil
}

func sortNodes(nodes []Node) {
	sort.Slice(nodes, func(i, j int) bool {
		leftRank := nodeRegionRank(nodes[i].Name)
		rightRank := nodeRegionRank(nodes[j].Name)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return nodes[i].Name < nodes[j].Name
	})
}

func nodeRegionRank(name string) int {
	switch {
	case strings.Contains(name, "香港"):
		return 0
	case strings.Contains(name, "新加坡"):
		return 1
	case strings.Contains(name, "日本"):
		return 2
	case strings.Contains(name, "美国"):
		return 3
	default:
		return 4
	}
}

func proxyURIs(value any) ([]string, error) {
	items, ok := proxyStringItems(value)
	if !ok {
		return nil, fmt.Errorf("expected a list of x365 URLs, got %T", value)
	}
	var uris []string
	for _, item := range items {
		raw := strings.TrimSpace(item)
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(raw, "x365://") {
			return nil, fmt.Errorf("unsupported proxy URL: %s", raw)
		}
		uris = append(uris, raw)
	}
	if len(uris) == 0 {
		return nil, errors.New("empty proxy URL list")
	}
	return uris, nil
}

func proxyTemplateURIs(value any, uuid string) ([]string, error) {
	items, ok := proxyStringItems(value)
	if !ok {
		return nil, fmt.Errorf("expected a list of x365 URL templates, got %T", value)
	}
	var uris []string
	for _, item := range items {
		raw := strings.TrimSpace(item)
		if raw == "" {
			continue
		}
		uri, err := fillProxyTemplateURI(raw, uuid)
		if err != nil {
			return nil, err
		}
		uris = append(uris, uri)
	}
	if len(uris) == 0 {
		return nil, errors.New("empty proxy URL template list")
	}
	return uris, nil
}

func proxyStringItems(value any) ([]string, bool) {
	switch items := value.(type) {
	case []string:
		return items, true
	case []any:
		uris := make([]string, 0, len(items))
		for _, item := range items {
			raw, ok := item.(string)
			if !ok {
				return nil, false
			}
			uris = append(uris, raw)
		}
		return uris, true
	default:
		return nil, false
	}
}

func fillProxyTemplateURI(raw, uuid string) (string, error) {
	if !strings.HasPrefix(raw, "x365://") {
		return "", fmt.Errorf("unsupported proxy URL template: %s", raw)
	}
	const emptyUserPrefix = "x365://@"
	if strings.HasPrefix(raw, emptyUserPrefix) {
		return "x365://" + uuid + raw[len("x365://"):], nil
	}
	return "", errors.New("x365 URL template must omit UUID as x365://@server...")
}

func parseNode(name, rawURI string) (Node, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return Node{}, err
	}
	if u.Scheme != "x365" {
		return Node{}, fmt.Errorf("not an x365 URL: %s", u.Scheme)
	}
	portText := u.Port()
	if u.User == nil || u.Hostname() == "" || portText == "" {
		return Node{}, errors.New("missing user, host, or port")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return Node{}, fmt.Errorf("invalid port: %q", portText)
	}
	q := u.Query()
	missing := missingQueryFields(q, "path", "host", "sni", "pbk", "sid")
	if len(missing) != 0 {
		return Node{}, fmt.Errorf("missing query fields: %s", strings.Join(missing, ", "))
	}
	if sid := q.Get("sid"); sid != "" {
		rawSID, err := hex.DecodeString(sid)
		if err != nil {
			return Node{}, fmt.Errorf("invalid short id: %w", err)
		}
		if len(rawSID) > 8 {
			return Node{}, fmt.Errorf("short id too long: %d", len(rawSID))
		}
	}
	return Node{
		Name:      strings.TrimSpace(name),
		UserID:    u.User.Username(),
		Server:    u.Hostname(),
		Port:      port,
		Path:      q.Get("path"),
		Host:      q.Get("host"),
		SNI:       q.Get("sni"),
		PublicKey: q.Get("pbk"),
		ShortID:   q.Get("sid"),

		fingerprint: q.Get("fp"),
	}, nil
}

func (n Node) Redacted() string {
	return fmt.Sprintf("%s %s:%d path=%s host=%s sni=%s", n.Name, n.Server, n.Port, n.Path, n.Host, n.SNI)
}

func missingQueryFields(q url.Values, fields ...string) []string {
	var missing []string
	for _, field := range fields {
		if q.Get(field) == "" {
			missing = append(missing, field)
		}
	}
	return missing
}
