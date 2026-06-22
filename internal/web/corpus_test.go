package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wewaf/internal/history"
)

func TestHandleCorpus(t *testing.T) {
	// Nil history store -> 200 with an empty report (no panic).
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleCorpus(rec, httptest.NewRequest(http.MethodGet, "/api/corpus", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("nil history: status %d want 200", rec.Code)
	}

	// Non-GET -> 405.
	rec = httptest.NewRecorder()
	s.handleCorpus(rec, httptest.NewRequest(http.MethodPost, "/api/corpus", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status %d want 405", rec.Code)
	}

	// Real store with blocks -> the rule surfaces in the JSON report.
	st, err := history.Open(history.Options{Dir: t.TempDir(), FlushEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("history open: %v", err)
	}
	defer st.Close()
	st.Start(context.Background())
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		st.EnqueueBlock(history.BlockEvent{Timestamp: now, IP: "203.0.113.9", RuleID: "XSS-001", RuleCategory: "xss", Score: 100})
	}
	srv := &Server{history: st}

	deadline := time.Now().Add(2 * time.Second)
	for {
		rec = httptest.NewRecorder()
		srv.handleCorpus(rec, httptest.NewRequest(http.MethodGet, "/api/corpus?hours=1&top=10", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("real store: status %d want 200", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "XSS-001") {
			return // success
		}
		if time.Now().After(deadline) {
			t.Fatalf("corpus endpoint never surfaced the block: %s", rec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
