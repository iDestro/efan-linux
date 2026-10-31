package efan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIClientCookiePersistence(t *testing.T) {
	var gotCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/login":
			http.SetCookie(w, &http.Cookie{
				Name:  "server_session_test",
				Value: "session-value",
				Path:  "/",
			})
			_, _ = io.WriteString(w, `{"access_token":"user-uuid"}`)
		case "/v1/whmcs/sso-login":
			gotCookie = r.Header.Get("Cookie")
			_, _ = io.WriteString(w, `{"url":"https://example.test/sso"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, nil, DeviceInfo{})
	client.NoDeviceHeaders = true
	if _, err := client.requestJSON(context.Background(), http.MethodPost, "/v1/login", []byte(`{}`), "", false); err != nil {
		t.Fatalf("login request: %v", err)
	}
	header := client.CookieHeader()
	if !strings.Contains(header, "server_session_test=session-value") {
		t.Fatalf("cookie header = %q, want persisted server session", header)
	}

	restored := NewAPIClient(server.URL, nil, DeviceInfo{})
	restored.NoDeviceHeaders = true
	if err := restored.SetCookieHeader(header); err != nil {
		t.Fatalf("restore cookie: %v", err)
	}
	if _, _, err := restored.SSOLogin(context.Background(), ""); err != nil {
		t.Fatalf("sso login: %v", err)
	}
	if !strings.Contains(gotCookie, "server_session_test=session-value") {
		t.Fatalf("server received cookie %q, want persisted server session", gotCookie)
	}
}

func TestSessionFromDataDoesNotUseAccessTokenAsSessionToken(t *testing.T) {
	session, err := sessionFromData("user@example.test", map[string]any{
		"access_token": "user-uuid",
	})
	if err != nil {
		t.Fatalf("sessionFromData: %v", err)
	}
	if session.SessionToken != "" {
		t.Fatalf("session token = %q, want empty until the cookie is captured", session.SessionToken)
	}
}

func TestClashSubscriptionURL(t *testing.T) {
	got, err := ClashSubscriptionURL("", "123456", "test-subscribe-token")
	if err != nil {
		t.Fatalf("ClashSubscriptionURL: %v", err)
	}
	want := DefaultClashBase + "/123456/test-subscribe-token/"
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}

	got, err = ClashSubscriptionURL("https://example.test/clash/", "123456", "token")
	if err != nil {
		t.Fatalf("ClashSubscriptionURL with base: %v", err)
	}
	if got != "https://example.test/clash/123456/token/" {
		t.Fatalf("URL = %q", got)
	}

	if _, err := ClashSubscriptionURL("", "", "token"); err == nil {
		t.Fatal("expected an error for an empty service id")
	}
	if _, err := ClashSubscriptionURL("", "123456", ""); err == nil {
		t.Fatal("expected an error for an empty subscription token")
	}
}

func TestAppDataParsesSubscriptionFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/app" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"code":0,"data":{"proxy":"payload","user":{"pid":123456,"whm_hosting_id":123456,"subscribe_token":"test-subscribe-token"}}}`)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, nil, DeviceInfo{})
	client.NoDeviceHeaders = true
	result, err := client.AppData(context.Background(), "access-token")
	if err != nil {
		t.Fatalf("AppData: %v", err)
	}
	if result.ServiceID != "123456" {
		t.Fatalf("service id = %q, want 123456", result.ServiceID)
	}
	if result.SubscribeToken != "test-subscribe-token" {
		t.Fatalf("subscribe token = %q, want test-subscribe-token", result.SubscribeToken)
	}
}

func TestRefreshWithoutNewTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/session/refresh" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"code":0,"message":"ok"}`)
	}))
	defer server.Close()

	client := NewAPIClient(server.URL, nil, DeviceInfo{})
	client.NoDeviceHeaders = true
	session, _, err := client.Refresh(context.Background(), "account-session-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if session.SessionToken != "account-session-token" {
		t.Fatalf("session token = %q, want original token", session.SessionToken)
	}
	if session.AccessToken != "" {
		t.Fatalf("access token = %q, want empty when the server returns no new token", session.AccessToken)
	}
}

func TestSessionFromDataSeparatesAccountAndServiceTokens(t *testing.T) {
	session, err := sessionFromData("user@example.test", map[string]any{
		"token": "account-session-token",
		"my_services": []any{
			map[string]any{"access_token": "service-access-token"},
		},
	})
	if err != nil {
		t.Fatalf("sessionFromData: %v", err)
	}
	if session.AccessToken != "service-access-token" {
		t.Fatalf("access token = %q, want service access token", session.AccessToken)
	}
	if session.SessionToken != "account-session-token" {
		t.Fatalf("session token = %q, want account session token", session.SessionToken)
	}
}
