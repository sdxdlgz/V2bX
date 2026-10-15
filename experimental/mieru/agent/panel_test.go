package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPanelContractAndRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test" || r.URL.Query().Get("node_id") != "1" {
			t.Error("bad authentication")
		}
		if r.URL.Path == "/api/v1/server/Mieru/snapshot" {
			json.NewEncoder(w).Encode(testSnapshot())
			return
		}
		if r.URL.Path == "/api/v1/server/Mieru/traffic" {
			w.Write([]byte(`{"accepted":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	p := &Panel{BaseURL: server.URL + "/", Token: "test", NodeID: 1}
	if _, err := p.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Report(context.Background(), Report{AgentID: "test", Counters: []Counter{}}); err != nil {
		t.Fatal(err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, server.URL, 302) }))
	defer redirect.Close()
	p.BaseURL = redirect.URL
	if _, err := p.Snapshot(context.Background()); err == nil {
		t.Fatal("followed credential redirect")
	}
	p.BaseURL = "http://example.com"
	if _, err := p.Snapshot(context.Background()); err == nil {
		t.Fatal("cleartext remote API accepted")
	}
}
