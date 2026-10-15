package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSourceBoundaries(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "10.0.0.1", "192.168.1.2", "169.254.169.254", "100.64.1.1", "198.18.0.1", "224.0.0.1"} {
		if publicIP(net.ParseIP(ip)) {
			t.Errorf("accepted private IP %s", ip)
		}
	}
	if !publicIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public IP rejected")
	}
	for _, source := range []string{"file:///etc/passwd", "http://example.com/sub", "https://user:pass@example.com/sub", "unknown://node"} {
		if _, err := fetchSource(context.Background(), Config{}, source); err == nil {
			t.Errorf("accepted invalid source %s", source)
		}
	}
	data, err := fetchSource(context.Background(), Config{}, "vless://test@example.com:443#node")
	if err != nil || !strings.HasPrefix(string(data), "vless://") {
		t.Fatal("URI was not preserved")
	}
	if allowedProtocol("Direct") || allowedProtocol("Compatible") || allowedProtocol("Selector") {
		t.Fatal("unsafe built-in accepted as upstream")
	}
}

func TestRevokedAndMalformedPanelSnapshots(t *testing.T) {
	var code atomic.Int32
	code.Store(403)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(code.Load()))
		_, _ = w.Write([]byte(`{"data":{"id":9,"revision":1,"enabled":true,"refresh_interval":3600}}`))
	}))
	defer server.Close()
	c := Config{PanelURL: server.URL, UpstreamID: 1, Token: strings.Repeat("a", 64)}
	if _, err := snapshot(context.Background(), c); err != errRevoked {
		t.Fatal("revocation was not distinguished")
	}
	code.Store(200)
	if _, err := snapshot(context.Background(), c); err == nil {
		t.Fatal("cross-binding response accepted")
	}
}

func TestRelayClosesOnRevoke(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, e := upstream.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	r, err := newRelay("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	r.set(upstream.Addr().String(), false)
	c, err := net.Dial("tcp", r.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("ping"))
	b := make([]byte, 4)
	if _, err = io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatal("relay failed")
	}
	r.set("", true)
	if _, err = c.Read(b); err == nil {
		t.Fatal("existing session survived revocation")
	}
	c2, _ := net.Dial("tcp", r.listener.Addr().String())
	defer c2.Close()
	_ = c2.SetDeadline(time.Now().Add(time.Second))
	if _, err = c2.Read(b); err == nil {
		t.Fatal("disabled relay allowed traffic")
	}
}

func TestRealCoreSelectionAndInvalidUpdates(t *testing.T) {
	binary := os.Getenv("MIHOMO_BINARY")
	if binary == "" {
		t.Skip("set MIHOMO_BINARY to run real pinned-core acceptance")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		request, err := http.ReadRequest(buffer.Reader)
		if err != nil {
			return
		}
		_ = request.Body.Close()
		_, _ = buffer.WriteString("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
		_ = buffer.Flush()
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	proxy := map[string]any{"name": "one", "type": "http", "server": host, "port": p}
	source, _ := json.Marshal(map[string]any{"proxies": []any{proxy}})
	c := Config{Mihomo: binary, StateDir: t.TempDir(), ProbeURL: "http://probe.invalid/generate_204"}
	ctx := context.Background()
	if err := checkCore(ctx, binary); err != nil {
		t.Fatal(err)
	}
	core, err := startCore(ctx, c, source, "")
	if err != nil {
		t.Fatal(err)
	}
	defer core.stop()
	if core.protocol != "Http" {
		t.Fatalf("unexpected protocol %q", core.protocol)
	}
	if _, err = startCore(ctx, c, []byte("broken: ["), ""); err == nil {
		t.Fatal("invalid source accepted")
	}
	if err = core.probe(ctx, c.ProbeURL); err != nil {
		t.Fatal("failed candidate disrupted current core")
	}
	proxy2 := map[string]any{"name": "two", "type": "http", "server": host, "port": p}
	multi, _ := json.Marshal(map[string]any{"proxies": []any{proxy, proxy2}})
	if _, err = startCore(ctx, c, multi, ""); err == nil || err.Error() != "select_node" {
		t.Fatal("multiple nodes auto-selected")
	}
	selected, err := startCore(ctx, c, multi, "two")
	if err != nil {
		t.Fatal(err)
	}
	selected.stop()
	direct := []byte(`{"proxies":[{"name":"escape","type":"direct"}]}`)
	if _, err = startCore(ctx, c, direct, ""); err == nil {
		t.Fatal("direct fallback accepted")
	}
}
