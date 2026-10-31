package efan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"

	"efan-linux/internal/x365"
)

var x365URLPattern = regexp.MustCompile(`x365://[^\s"'\\]+`)

// NormalizeProxyConfig turns the decrypted proxy payload into the YAML shape
// understood by the x365 adapter. The official payload is normally already
// `proxies: {name: [x365://...]}`, but older captures and diagnostics can be
// a bare map or a plain list of URLs.
func NormalizeProxyConfig(plain []byte) ([]byte, error) {
	text := strings.TrimSpace(strings.TrimPrefix(string(plain), "\ufeff"))
	if text == "" {
		return nil, errors.New("decrypted proxy payload is empty")
	}
	if out, ok := normalizeJSONProxy(text); ok {
		return out, nil
	}
	if out, ok := normalizeYAMLProxy(text); ok {
		return out, nil
	}
	if urls := extractX365URLs(text); len(urls) > 0 {
		return marshalProxyGroups([]string{"EFAN"}, [][]string{urls})
	}
	return nil, errors.New("decrypted proxy payload contains no x365:// nodes")
}

func normalizeJSONProxy(text string) ([]byte, bool) {
	var doc any
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return nil, false
	}
	if s, ok := doc.(string); ok {
		text = s
		if out, ok := normalizeYAMLProxy(text); ok {
			return out, true
		}
	}
	m, ok := doc.(map[string]any)
	if !ok {
		if list, ok := doc.([]any); ok {
			urls := stringsFromAnyList(list)
			if len(urls) > 0 {
				out, err := marshalProxyGroups([]string{"EFAN"}, [][]string{urls})
				return out, err == nil
			}
		}
		return nil, false
	}
	if raw, exists := m["proxies_tmpl"]; exists {
		if asString(raw) != "" || raw != nil {
			out, err := yaml.Marshal(m)
			return out, err == nil
		}
	}
	if raw, exists := m["proxies"]; exists {
		switch value := raw.(type) {
		case map[string]any:
			out, err := yaml.Marshal(map[string]any{"proxies": value})
			return out, err == nil
		case []any:
			urls := stringsFromAnyList(value)
			if len(urls) > 0 {
				out, err := marshalProxyGroups([]string{"EFAN"}, [][]string{urls})
				return out, err == nil
			}
		}
	}
	// A bare map of group names to URL lists.
	groups := make([]string, 0, len(m))
	groupURLs := make([][]string, 0, len(m))
	for name, value := range m {
		switch v := value.(type) {
		case string:
			if strings.HasPrefix(strings.TrimSpace(v), "x365://") {
				groups = append(groups, name)
				groupURLs = append(groupURLs, []string{strings.TrimSpace(v)})
			}
		case []any:
			urls := stringsFromAnyList(v)
			if len(urls) > 0 {
				groups = append(groups, name)
				groupURLs = append(groupURLs, urls)
			}
		}
	}
	if len(groups) > 0 {
		out, err := marshalProxyGroups(groups, groupURLs)
		return out, err == nil
	}
	return nil, false
}

func normalizeYAMLProxy(text string) ([]byte, bool) {
	var top yaml.MapSlice
	if err := yaml.Unmarshal([]byte(text), &top); err != nil || len(top) == 0 {
		return nil, false
	}
	hasProxies := false
	hasTemplate := false
	for _, item := range top {
		key := fmt.Sprint(item.Key)
		switch key {
		case "proxies":
			hasProxies = true
			switch value := item.Value.(type) {
			case yaml.MapSlice:
				return []byte(text), true
			case map[string]any:
				return []byte(text), true
			case []any:
				urls := stringsFromAnyList(value)
				if len(urls) > 0 {
					out, err := marshalProxyGroups([]string{"EFAN"}, [][]string{urls})
					return out, err == nil
				}
			case []string:
				if len(value) > 0 {
					out, err := marshalProxyGroups([]string{"EFAN"}, [][]string{value})
					return out, err == nil
				}
			case string:
				if strings.HasPrefix(strings.TrimSpace(value), "x365://") {
					out, err := marshalProxyGroups([]string{"EFAN"}, [][]string{{strings.TrimSpace(value)}})
					return out, err == nil
				}
			}
		case "proxies_tmpl":
			hasTemplate = true
		}
	}
	if hasTemplate {
		return []byte(text), true
	}
	if hasProxies {
		return nil, false
	}
	// A bare map of group names to URL lists (the common older shape).
	groups := make([]string, 0, len(top))
	groupURLs := make([][]string, 0, len(top))
	for _, item := range top {
		name := fmt.Sprint(item.Key)
		if name == "listen" || name == "log_path" || name == "sniff" {
			continue
		}
		urls := stringsFromYAMLValue(item.Value)
		if len(urls) > 0 {
			groups = append(groups, name)
			groupURLs = append(groupURLs, urls)
		}
	}
	if len(groups) > 0 {
		out, err := marshalProxyGroups(groups, groupURLs)
		return out, err == nil
	}
	return nil, false
}

func stringsFromYAMLValue(value any) []string {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(strings.TrimSpace(v), "x365://") {
			return []string{strings.TrimSpace(v)}
		}
	case []string:
		return filterX365(v)
	case []any:
		return stringsFromAnyList(v)
	case yaml.MapSlice:
		var out []string
		for _, item := range v {
			out = append(out, stringsFromYAMLValue(item.Value)...)
		}
		return out
	}
	return nil
}

func stringsFromAnyList(list []any) []string {
	var out []string
	for _, item := range list {
		if s, ok := item.(string); ok {
			s = strings.TrimSpace(s)
			if strings.HasPrefix(s, "x365://") {
				out = append(out, s)
			}
		}
	}
	return out
}

func filterX365(values []string) []string {
	var out []string
	for _, s := range values {
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "x365://") {
			out = append(out, s)
		}
	}
	return out
}

func marshalProxyGroups(groups []string, urls [][]string) ([]byte, error) {
	proxies := make(yaml.MapSlice, 0, len(groups))
	for i, group := range groups {
		list := make([]any, 0, len(urls[i]))
		for _, url := range urls[i] {
			list = append(list, url)
		}
		proxies = append(proxies, yaml.MapItem{Key: group, Value: list})
	}
	doc := yaml.MapSlice{{Key: "proxies", Value: proxies}}
	return yaml.Marshal(doc)
}

func extractX365URLs(text string) []string {
	matches := x365URLPattern.FindAllString(text, -1)
	seen := map[string]bool{}
	var out []string
	for _, match := range matches {
		match = strings.TrimRight(match, ",;)}]")
		if match == "" || seen[match] {
			continue
		}
		seen[match] = true
		out = append(out, match)
	}
	return out
}

// WriteProxyConfig validates the normalized node file with the same parser the
// adapter uses, then atomically installs it at path. On failure the decrypted
// payload is preserved at plaintextPath for diagnosis.
func WriteProxyConfig(path, plaintextPath string, plain []byte) (int, error) {
	normalized, err := NormalizeProxyConfig(plain)
	if err != nil {
		_ = writeFile0600(plaintextPath, plain)
		return 0, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return 0, err
	}
	if _, err := tmp.Write(normalized); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	cfg, err := x365.LoadConfig(tmpName)
	if err != nil {
		_ = writeFile0600(plaintextPath, plain)
		return 0, fmt.Errorf("decrypted proxy payload did not validate: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return 0, err
	}
	_ = os.Chmod(path, 0o600)
	return len(cfg.Nodes), nil
}
