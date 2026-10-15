package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxSourceBytes = 2 << 20

func publicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, block := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4"} {
		_, network, _ := net.ParseCIDR(block)
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func sourceDialer(allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid source address")
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("source DNS failed")
		}
		for _, ip := range ips {
			if !allowPrivate && !publicIP(ip.IP) {
				return nil, errors.New("private source address rejected")
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}

func fetchSource(ctx context.Context, c Config, source string) ([]byte, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, errors.New("source_fetch")
	}
	if u.Scheme != "https" {
		for _, scheme := range []string{"vless", "vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "mierus"} {
			if u.Scheme == scheme && len(source) <= maxSourceBytes {
				return []byte(source), nil
			}
		}
		return nil, errors.New("source_fetch")
	}
	if u.User != nil || u.Host == "" {
		return nil, errors.New("source_fetch")
	}
	transport := &http.Transport{DialContext: sourceDialer(c.AllowPrivateSources), TLSHandshakeTimeout: 8 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.User != nil {
			return errors.New("source redirect rejected")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, errors.New("source_fetch")
	}
	req.Header.Set("User-Agent", "clash.meta/1.19.32 V2bX-Upstream/1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("source_fetch")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("source_fetch")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxSourceBytes || strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("source_fetch")
	}
	return data, nil
}
