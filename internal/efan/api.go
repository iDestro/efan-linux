package efan

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAPIBase   = "https://api.efanapp.com"
	DefaultClashBase = "https://api.efanyunapi.com/clash"
)

type APIClient struct {
	BaseURL         string
	HTTP            *http.Client
	Key             *rsa.PrivateKey
	Device          DeviceInfo
	UserAgent       string
	NoDeviceHeaders bool
	Debug           bool
}

type APIError struct {
	Status  int
	Code    int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Status != 0 {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return "API request failed"
}

func IsAuthError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	if apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden {
		return true
	}
	message := apiErr.Message
	return strings.Contains(message, "登录") || strings.Contains(message, "过期") || strings.Contains(message, "无权")
}

type LoginResult struct {
	Session Session
	Data    any
}

type AppDataResult struct {
	Data           any
	Proxy          string
	AccessToken    string
	SessionToken   string
	ServiceID      string
	SubscribeToken string
	Services       []Service
}

func NewAPIClient(baseURL string, key *rsa.PrivateKey, device DeviceInfo) *APIClient {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultAPIBase
	}
	// Do not use ProxyFromEnvironment: the desktop session may still point at a
	// dead local proxy, and the Efan API is reachable directly.
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	jar, _ := cookiejar.New(nil)
	return &APIClient{
		BaseURL:   baseURL,
		HTTP:      &http.Client{Transport: transport, Timeout: 45 * time.Second, Jar: jar},
		Key:       key,
		Device:    device,
		UserAgent: "efanapp/" + device.AppVersion + " (Windows NT 10.0; Win64; x64)",
	}
}

// SetCookieHeader restores the API server session from a serialized Cookie
// header. The website uses an HttpOnly server_session_* cookie for WHMCS SSO;
// it is separate from the bearer token and must survive across CLI runs.
func (c *APIClient) SetCookieHeader(header string) error {
	header = strings.TrimSpace(header)
	if header == "" {
		return nil
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return fmt.Errorf("parse API base URL: %w", err)
	}
	var cookies []*http.Cookie
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			continue
		}
		cookies = append(cookies, &http.Cookie{
			Name:  name,
			Value: strings.TrimSpace(value),
			Path:  "/",
		})
	}
	if len(cookies) == 0 {
		return errors.New("cookie header contains no valid cookies")
	}
	c.HTTP.Jar.SetCookies(base, cookies)
	return nil
}

// CookieHeader serializes the current API server session so it can be stored
// next to the bearer/session tokens in the private session file.
func (c *APIClient) CookieHeader() string {
	if c.HTTP == nil || c.HTTP.Jar == nil {
		return ""
	}
	base, err := url.Parse(c.BaseURL)
	if err != nil {
		return ""
	}
	cookies := c.HTTP.Jar.Cookies(base)
	if len(cookies) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

func (c *APIClient) Login(ctx context.Context, email, password string) (LoginResult, error) {
	body, err := json.Marshal(map[string]string{"email": email, "password": password})
	if err != nil {
		return LoginResult{}, err
	}
	data, err := c.requestJSON(ctx, http.MethodPost, "/v1/login", body, "", true)
	if err != nil {
		return LoginResult{}, err
	}
	data = unwrapJSON(data)
	session, err := sessionFromData(email, data)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Session: session, Data: data}, nil
}

func (c *APIClient) Refresh(ctx context.Context, sessionToken string) (Session, any, error) {
	payload := map[string]string{}
	if token := strings.TrimSpace(sessionToken); token != "" {
		payload["session_token"] = token
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Session{}, nil, err
	}
	data, err := c.requestJSON(ctx, http.MethodPost, "/v1/session/refresh", body, "", true)
	if err != nil {
		return Session{}, nil, err
	}
	data = unwrapJSON(data)
	session, err := sessionFromData("", data)
	if err != nil {
		// /v1/session/refresh normally returns only {"code":0,"message":...};
		// the server refreshes the account session in place. Keep the existing
		// access token and treat this as a successful refresh.
		if findString(data, "access_token", "token", "session_token", "account_session_token", "refresh_token") == "" {
			return Session{SessionToken: sessionToken}, data, nil
		}
		return Session{}, data, err
	}
	// If the refresh response only rotated the access token, keep the original
	// session token instead of the fallback value chosen by sessionFromData.
	if findString(data, "session_token", "account_session_token", "refresh_token") == "" {
		session.SessionToken = sessionToken
	}
	return session, data, nil
}

func (c *APIClient) AppData(ctx context.Context, accessToken string) (AppDataResult, error) {
	data, err := c.requestJSON(ctx, http.MethodGet, "/v1/app?flag=wassvpn", nil, accessToken, true)
	if err != nil {
		return AppDataResult{}, err
	}
	data = unwrapJSON(data)
	result := AppDataResult{Data: data}
	result.Proxy = findString(data, "proxy")
	result.AccessToken = findString(data, "access_token")
	result.SessionToken = findString(data, "session_token", "account_session_token")
	result.Services = parseServices(data)
	// The Clash subscription is served as
	// <base>/<whmcs-service-id>/<subscribe-token>/. Prefer the user object so
	// unrelated service fields cannot provide the wrong id or token.
	if userValue, found := findValueExact(data, "user"); found {
		if user, ok := userValue.(map[string]any); ok {
			result.ServiceID = findString(user, "whm_hosting_id", "pid", "service_id")
			result.SubscribeToken = findString(user, "subscribe_token", "subscription_token")
		}
	}
	if result.ServiceID == "" {
		result.ServiceID = findString(data, "whm_hosting_id", "pid", "service_id")
	}
	if result.SubscribeToken == "" {
		result.SubscribeToken = findString(data, "subscribe_token", "subscription_token")
	}
	if result.Proxy == "" {
		return result, ErrNoProxy
	}
	return result, nil
}

// ClashSubscriptionURL builds the direct Clash/Mihomo subscription URL from
// the service id and subscribe token returned by /v1/app. The base can be
// overridden for testing or if Efan changes the subscription host.
func ClashSubscriptionURL(base, serviceID, subscribeToken string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	serviceID = strings.TrimSpace(serviceID)
	subscribeToken = strings.TrimSpace(subscribeToken)
	if base == "" {
		base = DefaultClashBase
	}
	if serviceID == "" {
		return "", errors.New("subscription service id is missing")
	}
	if subscribeToken == "" {
		return "", errors.New("subscription token is missing")
	}
	return base + "/" + url.PathEscape(serviceID) + "/" + url.PathEscape(subscribeToken) + "/", nil
}

func (c *APIClient) SSOLogin(ctx context.Context, sessionToken string) (string, any, error) {
	payload := map[string]string{}
	if token := strings.TrimSpace(sessionToken); token != "" {
		payload["session_token"] = token
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", nil, err
	}
	data, err := c.requestJSON(ctx, http.MethodPost, "/v1/whmcs/sso-login", body, "", true)
	if err != nil {
		return "", nil, err
	}
	data = unwrapJSON(data)
	url := findString(data, "url", "login_url", "sso_url", "redirect_url")
	if url == "" {
		if s, ok := data.(string); ok && strings.HasPrefix(s, "http") {
			url = s
		}
	}
	if url == "" {
		return "", data, errors.New("SSO response did not contain a URL")
	}
	return url, data, nil
}

func (c *APIClient) requestJSON(ctx context.Context, method, path string, body []byte, accessToken string, withDevice bool) (any, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "zh-CN")
	req.Header.Set("Content-Language", "zh-CN")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if withDevice && !c.NoDeviceHeaders {
		headers, err := DeviceHeaders(c.Device, c.Key)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", path, err)
	}
	if c.Debug {
		log.Printf("%s %s -> HTTP %d, %d bytes", method, path, resp.StatusCode, len(raw))
		if keys := describeJSONKeys(raw); keys != "" {
			log.Printf("response key tree: %s", keys)
		}
	}
	return parseAPIResponse(resp.StatusCode, raw)
}

func parseAPIResponse(status int, raw []byte) (any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, &APIError{Status: status, Message: fmt.Sprintf("empty response (HTTP %d)", status)}
	}
	var envelope struct {
		Code    json.RawMessage `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	jsonErr := json.Unmarshal(raw, &envelope)
	if jsonErr != nil {
		return nil, &APIError{Status: status, Message: fmt.Sprintf("HTTP %d: %s", status, truncateText(string(raw), 200))}
	}
	code, hasCode := parseResponseCode(envelope.Code)
	if status >= 400 || (hasCode && code != 0 && code != 200) {
		message := strings.TrimSpace(envelope.Message)
		if message == "" && len(envelope.Data) > 0 && string(envelope.Data) != "null" {
			var nested any
			if json.Unmarshal(envelope.Data, &nested) == nil {
				message = findString(nested, "message", "error", "msg")
			}
		}
		if message == "" {
			message = fmt.Sprintf("HTTP %d", status)
		}
		return nil, &APIError{Status: status, Code: code, Message: message}
	}
	// Return the whole JSON document. All callers use recursive lookups, so
	// both a bare app-data object and an envelope like
	// {"code":0,"data":{...}} work without guessing which shape the server
	// chose for this endpoint.
	var whole any
	if err := json.Unmarshal(raw, &whole); err != nil {
		return nil, err
	}
	return whole, nil
}

func parseResponseCode(raw json.RawMessage) (int, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return 0, false
	}
	var number int
	if json.Unmarshal(raw, &number) == nil {
		return number, true
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		if number, err := strconv.Atoi(strings.TrimSpace(text)); err == nil {
			return number, true
		}
	}
	return 0, false
}

func sessionFromData(email string, data any) (Session, error) {
	data = unwrapJSON(data)
	// Efan login responses have two different tokens:
	//   - data.my_services[].access_token: bearer token for /v1/app
	//   - data.token: account session token used by /v1/session/refresh and
	//     /v1/whmcs/sso-login
	// Older/simpler responses may only have data.token, in which case it has
	// to serve as both.
	access := findString(data, "access_token")
	topToken := findString(data, "token")
	sessionToken := findString(data, "session_token", "account_session_token", "refresh_token")
	if sessionToken == "" {
		sessionToken = topToken
	}
	if access == "" {
		access = topToken
	}
	if access == "" && sessionToken != "" {
		access = sessionToken
	}
	expires := findTimestamp(data, "expires_at", "expired_at", "expire_time", "expires")
	services := parseServices(data)
	if access == "" {
		return Session{}, errors.New("login response did not contain access_token")
	}
	return Session{
		Email:        email,
		AccessToken:  access,
		SessionToken: sessionToken,
		ExpiresAt:    expires,
		Services:     services,
	}, nil
}

func parseServices(data any) []Service {
	items := findSlice(data, "my_services", "services")
	if items == nil {
		return nil
	}
	var out []Service
	seen := map[string]bool{}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		svc := Service{
			ServiceID:      findString(m, "service_id", "id", "serviceId"),
			Name:           findString(m, "name", "service_name", "product_name", "title"),
			SubscribeToken: findString(m, "subscribe_token", "subscription_token", "subscribeToken"),
			ExpiresAt:      formatValue(findValue(m, "expires_at", "expired_at", "expires", "end_at")),
			Traffic:        formatValue(findValue(m, "traffic", "used_traffic", "traffic_used", "data_usage")),
		}
		key := svc.ServiceID + "|" + svc.Name + "|" + svc.SubscribeToken
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, svc)
	}
	return out
}

func unwrapJSON(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") {
		return v
	}
	var parsed any
	if json.Unmarshal([]byte(s), &parsed) == nil {
		return parsed
	}
	return v
}

func findValue(v any, keys ...string) any {
	for _, key := range keys {
		if found, ok := findValueExact(v, key); ok {
			return found
		}
	}
	return nil
}

func findValueExact(v any, key string) (any, bool) {
	switch x := v.(type) {
	case map[string]any:
		if value, ok := x[key]; ok {
			return value, true
		}
		for _, value := range x {
			if found, ok := findValueExact(value, key); ok {
				return found, true
			}
		}
	case []any:
		for _, item := range x {
			if found, ok := findValueExact(item, key); ok {
				return found, true
			}
		}
	case string:
		trimmed := strings.TrimSpace(x)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			var parsed any
			if json.Unmarshal([]byte(trimmed), &parsed) == nil {
				if found, ok := findValueExact(parsed, key); ok {
					return found, true
				}
			}
		}
	}
	return nil, false
}

func findString(v any, keys ...string) string {
	return asString(findValue(v, keys...))
}

func findSlice(v any, keys ...string) []any {
	value := findValue(v, keys...)
	switch x := value.(type) {
	case []any:
		return x
	case map[string]any:
		// Some APIs return {"1": {...}} instead of a list.
		out := make([]any, 0, len(x))
		for _, item := range x {
			out = append(out, item)
		}
		return out
	default:
		return nil
	}
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case json.Number:
		return x.String()
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

func formatValue(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case float64:
		return asString(x)
	case map[string]any, []any:
		data, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(data)
	default:
		return fmt.Sprint(x)
	}
}

func findTimestamp(v any, keys ...string) int64 {
	value := findValue(v, keys...)
	switch x := value.(type) {
	case float64:
		return normalizeUnix(x)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return normalizeUnix(float64(n))
		}
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return normalizeUnix(float64(n))
		}
		layouts := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02", "2006/01/02"}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, s); err == nil {
				return t.Unix()
			}
		}
	}
	return 0
}

func normalizeUnix(value float64) int64 {
	if value <= 0 {
		return 0
	}
	if value > 1e12 {
		return int64(value / 1000)
	}
	if value > 1e9 {
		return int64(value)
	}
	// Small values are probably durations or token lifetimes; do not pretend
	// they are Unix timestamps in 1970.
	return 0
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// describeJSONKeys prints field names only, never values, so --debug can help
// diagnose a schema change without leaking tokens or node UUIDs.
func describeJSONKeys(raw []byte) string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return ""
	}
	keys := collectJSONKeys(value, "", 0, 0)
	if len(keys) > 60 {
		keys = append(keys[:60], "...")
	}
	return strings.Join(keys, ", ")
}

func collectJSONKeys(value any, prefix string, depth, budget int) []string {
	if depth > 2 || budget > 60 {
		return nil
	}
	var keys []string
	switch x := value.(type) {
	case map[string]any:
		names := make([]string, 0, len(x))
		for name := range x {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			full := name
			if prefix != "" {
				full = prefix + "." + name
			}
			keys = append(keys, full)
			keys = append(keys, collectJSONKeys(x[name], full, depth+1, len(keys))...)
			if len(keys) > 60 {
				return keys
			}
		}
	case []any:
		if len(x) > 0 {
			keys = append(keys, prefix+"[]")
			keys = append(keys, collectJSONKeys(x[0], prefix+"[]", depth+1, 0)...)
		}
	}
	return keys
}
