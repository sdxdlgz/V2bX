package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Core struct {
	cmd                                        *exec.Cmd
	done                                       chan struct{}
	once                                       sync.Once
	dir, address, controller, secret, protocol string
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func checkCore(ctx context.Context, binary string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "-v").Output()
	if err != nil || !strings.HasPrefix(string(output), "Mihomo ") || !strings.Contains(" "+string(output), " "+coreVersion+" ") {
		return errors.New("unsupported_core")
	}
	return nil
}

func startCore(ctx context.Context, c Config, source []byte, selector string) (*Core, error) {
	port, err := freePort()
	if err != nil {
		return nil, errors.New("core_start")
	}
	control, err := freePort()
	if err != nil {
		return nil, errors.New("core_start")
	}
	dir, err := os.MkdirTemp(c.StateDir, "core-")
	if err != nil {
		return nil, errors.New("core_start")
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("core_start")
	}
	core := &Core{dir: dir, address: fmt.Sprintf("127.0.0.1:%d", port), controller: fmt.Sprintf("http://127.0.0.1:%d", control), secret: hex.EncodeToString(random), done: make(chan struct{})}
	config := map[string]any{
		"mixed-port": port, "bind-address": "127.0.0.1", "allow-lan": false, "mode": "rule", "log-level": "silent", "ipv6": false,
		"external-controller": fmt.Sprintf("127.0.0.1:%d", control), "secret": core.secret,
		"profile":         map[string]any{"store-selected": false, "store-fake-ip": false},
		"proxy-providers": map[string]any{"upstream": map[string]any{"type": "file", "path": "./source", "health-check": map[string]any{"enable": false}}},
		"proxy-groups":    []any{map[string]any{"name": "UPSTREAM", "type": "select", "use": []string{"upstream"}}},
		"rules":           []string{"MATCH,UPSTREAM"},
	}
	data, _ := json.Marshal(config)
	if os.WriteFile(filepath.Join(dir, "source"), source, 0600) != nil || os.WriteFile(filepath.Join(dir, "config.json"), data, 0600) != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("core_start")
	}
	core.cmd = exec.Command(c.Mihomo, "-d", dir, "-f", filepath.Join(dir, "config.json"))
	configureChild(core.cmd)
	core.cmd.Stdout = io.Discard
	core.cmd.Stderr = io.Discard
	if core.cmd.Start() != nil {
		_ = os.RemoveAll(dir)
		return nil, errors.New("core_start")
	}
	go func() { _ = core.cmd.Wait(); close(core.done) }()
	if err = core.prepare(ctx, selector); err != nil {
		core.stop()
		return nil, err
	}
	if err = core.probe(ctx, c.ProbeURL); err != nil {
		core.stop()
		return nil, err
	}
	return core, nil
}

func (c *Core) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.controller+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.secret)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return nil, errors.New("core API failed")
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func (c *Core) prepare(ctx context.Context, selector string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return errors.New("invalid_subscription")
		case <-c.done:
			return errors.New("core_start")
		case <-ticker.C:
		}
		data, err := c.request(ctx, "GET", "/providers/proxies/upstream", nil)
		if err != nil {
			continue
		}
		var provider struct {
			Proxies []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"proxies"`
		}
		if json.Unmarshal(data, &provider) != nil || len(provider.Proxies) == 0 {
			continue
		}
		if selector == "" && len(provider.Proxies) != 1 {
			return errors.New("select_node")
		}
		for _, proxy := range provider.Proxies {
			if selector != "" && proxy.Name != selector {
				continue
			}
			if !allowedProtocol(proxy.Type) {
				return errors.New("invalid_subscription")
			}
			_, err = c.request(ctx, "PUT", "/proxies/UPSTREAM", map[string]string{"name": proxy.Name})
			if err != nil {
				return errors.New("invalid_subscription")
			}
			c.protocol = proxy.Type
			return nil
		}
		return errors.New("select_node")
	}
}

func allowedProtocol(name string) bool {
	// Explicitly excludes built-in DIRECT/COMPATIBLE and nested selector types.
	switch strings.ToLower(name) {
	case "vless", "vmess", "trojan", "shadowsocks", "shadowsocksr", "hysteria", "hysteria2", "tuic", "anytls", "mieru", "snell", "socks5", "http", "wireguard", "ssh":
		return true
	}
	return false
}

func (c *Core) probe(ctx context.Context, target string) error {
	proxy, _ := url.Parse("http://" + c.address)
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return errors.New("probe_failed")
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("probe_failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return errors.New("probe_failed")
	}
	return nil
}

func (c *Core) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *Core) stop() {
	c.once.Do(func() {
		if c.alive() {
			_ = terminateChild(c.cmd)
			select {
			case <-c.done:
			case <-time.After(2 * time.Second):
				_ = c.cmd.Process.Kill()
				<-c.done
			}
		}
		_ = os.RemoveAll(c.dir)
	})
}
