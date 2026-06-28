package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestParseConfigValue(t *testing.T) {
	cases := []struct {
		in   string
		want any
	}{
		{"true", true},
		{"false", false},
		{"42", 42},
		{"active", "active"},
		{`"quoted"`, "quoted"},
	}
	for _, c := range cases {
		if got := parseConfigValue(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseConfigValue(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

// capturingServer records the last request method/path/header/body so tests can
// assert wafctl builds requests correctly.
type capture struct {
	method string
	path   string
	apiKey string
	body   map[string]any
}

func newServer(t *testing.T, status int, resp string, cap *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.path = r.URL.RequestURI()
		cap.apiKey = r.Header.Get("X-API-Key")
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			cap.body = map[string]any{}
			_ = json.Unmarshal(b, &cap.body)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
}

func TestBanBuildsRequest(t *testing.T) {
	var cap capture
	srv := newServer(t, 200, `{"status":"ok"}`, &cap)
	defer srv.Close()

	var out, errb bytes.Buffer
	code := run([]string{"--addr", srv.URL, "--key", "secret", "ban", "--reason", "scanner", "--for", "1h", "203.0.113.7"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if cap.method != http.MethodPost || cap.path != "/api/bans" {
		t.Fatalf("got %s %s, want POST /api/bans", cap.method, cap.path)
	}
	if cap.apiKey != "secret" {
		t.Fatalf("X-API-Key=%q, want secret", cap.apiKey)
	}
	if cap.body["ip"] != "203.0.113.7" || cap.body["reason"] != "scanner" {
		t.Fatalf("body=%v", cap.body)
	}
	if d, _ := cap.body["duration_sec"].(float64); d != 3600 {
		t.Fatalf("duration_sec=%v, want 3600", cap.body["duration_sec"])
	}
}

func TestUnbanBuildsRequest(t *testing.T) {
	var cap capture
	srv := newServer(t, 200, `{"status":"ok"}`, &cap)
	defer srv.Close()

	var out, errb bytes.Buffer
	code := run([]string{"--addr", srv.URL, "--key", "k", "unban", "203.0.113.7"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if cap.method != http.MethodDelete || cap.path != "/api/bans?ip=203.0.113.7" {
		t.Fatalf("got %s %s, want DELETE /api/bans?ip=203.0.113.7", cap.method, cap.path)
	}
}

func TestConfigSetSendsSingleField(t *testing.T) {
	var cap capture
	srv := newServer(t, 200, `{"status":"ok"}`, &cap)
	defer srv.Close()

	var out, errb bytes.Buffer
	code := run([]string{"--addr", srv.URL, "--key", "k", "config", "set", "shaper_enabled", "true"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if cap.method != http.MethodPost || cap.path != "/api/config" {
		t.Fatalf("got %s %s, want POST /api/config", cap.method, cap.path)
	}
	if len(cap.body) != 1 || cap.body["shaper_enabled"] != true {
		t.Fatalf("body=%v, want single field shaper_enabled=true", cap.body)
	}
}

func TestConfigGetSingleField(t *testing.T) {
	var cap capture
	srv := newServer(t, 200, `{"mode":"active","block_threshold":40}`, &cap)
	defer srv.Close()

	var out, errb bytes.Buffer
	code := run([]string{"--addr", srv.URL, "--key", "k", "config", "get", "mode"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if cap.method != http.MethodGet || cap.path != "/api/config" {
		t.Fatalf("got %s %s, want GET /api/config", cap.method, cap.path)
	}
	if strings.TrimSpace(out.String()) != `"active"` {
		t.Fatalf("output=%q, want \"active\"", out.String())
	}
}

func TestStatusGet(t *testing.T) {
	var cap capture
	srv := newServer(t, 200, `{"status":"healthy"}`, &cap)
	defer srv.Close()
	var out, errb bytes.Buffer
	if code := run([]string{"--addr", srv.URL, "status"}, &out, &errb); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, errb.String())
	}
	if cap.path != "/api/health" {
		t.Fatalf("path=%s, want /api/health", cap.path)
	}
}

func TestNon200IsError(t *testing.T) {
	var cap capture
	srv := newServer(t, http.StatusServiceUnavailable, "auth required", &cap)
	defer srv.Close()
	var out, errb bytes.Buffer
	if code := run([]string{"--addr", srv.URL, "status"}, &out, &errb); code != 1 {
		t.Fatalf("exit=%d, want 1 on HTTP 503", code)
	}
	if !strings.Contains(errb.String(), "503") {
		t.Fatalf("stderr should mention 503: %q", errb.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"frobnicate"}, &out, &errb); code != 2 {
		t.Fatalf("exit=%d, want 2 for unknown command", code)
	}
}
