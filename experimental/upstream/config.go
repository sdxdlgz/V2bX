package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	PanelURL            string `json:"panel_url"`
	UpstreamID          int    `json:"upstream_id"`
	Token               string `json:"token"`
	Mihomo              string `json:"mihomo"`
	Listen              string `json:"listen"`
	StateDir            string `json:"state_dir"`
	ProbeURL            string `json:"probe_url"`
	AllowPrivateSources bool   `json:"allow_private_sources,omitempty"`
}

func readConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, errors.New("invalid configuration JSON")
	}
	u, err := url.Parse(c.PanelURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return c, errors.New("invalid panel URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback()) {
		return c, errors.New("panel URL requires HTTPS (HTTP allowed only on loopback for tests)")
	}
	if c.UpstreamID <= 0 || len(c.Token) != 64 {
		return c, errors.New("missing upstream ID or token")
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:19090"
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || !net.ParseIP(host).IsLoopback() || port == "0" {
		return c, errors.New("listener must use a fixed loopback port")
	}
	if !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.Mihomo) {
		return c, errors.New("state_dir and mihomo must be absolute paths")
	}
	if c.ProbeURL == "" {
		c.ProbeURL = "https://www.gstatic.com/generate_204"
	}
	p, err := url.Parse(c.ProbeURL)
	if err != nil || p.Host == "" || p.User != nil || (p.Scheme != "https" && p.Scheme != "http") {
		return c, errors.New("invalid probe URL")
	}
	return c, nil
}

type Snapshot struct {
	ID              int    `json:"id"`
	Revision        int    `json:"revision"`
	Enabled         bool   `json:"enabled"`
	Source          string `json:"source"`
	Selector        string `json:"selector"`
	RefreshInterval int    `json:"refresh_interval"`
}

type Report struct {
	Revision        int    `json:"revision"`
	AppliedRevision *int   `json:"applied_revision,omitempty"`
	Status          string `json:"status"`
	ErrorCode       string `json:"error_code,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
}

const pollInterval = 5 * time.Second
const leaseTimeout = 60 * time.Second
const coreVersion = "v1.19.32"
