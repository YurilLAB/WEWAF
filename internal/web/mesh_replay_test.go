package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wewaf/internal/config"
	"wewaf/internal/core"
)

func TestMeshReplayGuardFreshAccepted(t *testing.T) {
	g := newMeshReplayGuard(300)
	now := int64(1_000_000)
	if ok, reason := g.check("n1", now, now); !ok {
		t.Fatalf("fresh unique message should pass, got %q", reason)
	}
}

func TestMeshReplayGuardRejectsReplay(t *testing.T) {
	g := newMeshReplayGuard(300)
	now := int64(1_000_000)
	if ok, _ := g.check("dup", now, now); !ok {
		t.Fatal("first use should pass")
	}
	if ok, reason := g.check("dup", now, now+5); ok || reason != "replayed nonce" {
		t.Fatalf("replay should be rejected, got ok=%v reason=%q", ok, reason)
	}
}

func TestMeshReplayGuardRejectsStaleAndFuture(t *testing.T) {
	g := newMeshReplayGuard(300)
	now := int64(1_000_000)
	if ok, _ := g.check("old", now-301, now); ok {
		t.Fatal("stale timestamp (>window in past) must be rejected")
	}
	if ok, _ := g.check("fut", now+301, now); ok {
		t.Fatal("future timestamp (>window ahead) must be rejected")
	}
	// Just inside the window is allowed.
	if ok, _ := g.check("edge", now-299, now); !ok {
		t.Fatal("timestamp within window should pass")
	}
}

func TestMeshReplayGuardRejectsMissing(t *testing.T) {
	g := newMeshReplayGuard(300)
	if ok, _ := g.check("", 1000, 1000); ok {
		t.Fatal("missing nonce must be rejected")
	}
	if ok, _ := g.check("n", 0, 1000); ok {
		t.Fatal("missing timestamp must be rejected")
	}
}

func TestMeshReplayGuardExpiredNonceForgotten(t *testing.T) {
	g := newMeshReplayGuard(300)
	base := int64(1_000_000)
	if ok, _ := g.check("x", base, base); !ok {
		t.Fatal("first use should pass")
	}
	// Long after the window, the same nonce with a fresh timestamp passes again
	// (it would have been evicted; freshness alone protects beyond the window).
	later := base + 10_000
	if ok, reason := g.check("x", later, later); !ok {
		t.Fatalf("nonce reuse far outside the window with a fresh ts should pass, got %q", reason)
	}
}

// FuzzMeshReplayGuardCheck asserts check never panics on arbitrary input and
// always honors freshness (anything outside the window is rejected regardless
// of nonce).
func FuzzMeshReplayGuardCheck(f *testing.F) {
	f.Add("nonce", int64(100), int64(100))
	f.Add("", int64(0), int64(0))
	f.Add("x", int64(-5), int64(1<<40))
	f.Fuzz(func(t *testing.T, nonce string, ts, now int64) {
		g := newMeshReplayGuard(300)
		ok, reason := g.check(nonce, ts, now)
		if ok && reason != "" {
			t.Fatalf("ok=true must carry empty reason, got %q", reason)
		}
		// Freshness invariant: a passing message must be within the window and
		// have a non-empty nonce + non-zero ts.
		if ok {
			skew := now - ts
			if skew < 0 {
				skew = -skew
			}
			if nonce == "" || ts == 0 || skew > 300 {
				t.Fatalf("guard accepted an out-of-policy message: nonce=%q ts=%d now=%d", nonce, ts, now)
			}
		}
	})
}

// TestHandleMeshSyncDefenseEndToEnd proves the wired endpoint actually blocks
// unauthenticated, stale, and replayed syncs while accepting a fresh one.
func TestHandleMeshSyncDefenseEndToEnd(t *testing.T) {
	s := &Server{cfg: &config.Config{}, meshAPIKey: "secret-mesh-key"}

	post := func(key string, body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/mesh/sync", bytes.NewReader(b))
		if key != "" {
			req.Header.Set("X-Mesh-Key", key)
		}
		rec := httptest.NewRecorder()
		s.handleMeshSync(rec, req)
		return rec
	}
	now := time.Now().Unix()

	// Wrong key -> 401.
	if rec := post("nope", map[string]any{"bans": []core.BanEntry{}, "ts": now, "nonce": "a"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad key: status=%d, want 401", rec.Code)
	}
	// Fresh + authed -> 200.
	if rec := post("secret-mesh-key", map[string]any{"bans": []core.BanEntry{}, "ts": now, "nonce": "fresh-1"}); rec.Code != http.StatusOK {
		t.Fatalf("fresh authed sync: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	// Replay of the same nonce -> 400.
	if rec := post("secret-mesh-key", map[string]any{"bans": []core.BanEntry{}, "ts": now, "nonce": "fresh-1"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed nonce: status=%d, want 400", rec.Code)
	}
	// Stale timestamp -> 400.
	if rec := post("secret-mesh-key", map[string]any{"bans": []core.BanEntry{}, "ts": now - 100000, "nonce": "fresh-2"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("stale ts: status=%d, want 400", rec.Code)
	}
	// Missing nonce -> 400.
	if rec := post("secret-mesh-key", map[string]any{"bans": []core.BanEntry{}, "ts": now}); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing nonce: status=%d, want 400", rec.Code)
	}
}
