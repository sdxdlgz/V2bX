package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Panel struct {
	BaseURL string
	Token   string
	NodeID  int
	Client  *http.Client
}

func (p *Panel) request(ctx context.Context, method, action string, body, target any) error {
	endpoint, err := url.Parse(p.BaseURL)
	if err != nil || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || p.NodeID < 1 || p.Token == "" {
		return errors.New("invalid panel configuration")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && (endpoint.Hostname() == "127.0.0.1" || endpoint.Hostname() == "localhost" || endpoint.Hostname() == "::1")) {
		return errors.New("panel requires HTTPS (HTTP allowed only on loopback for tests)")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/v1/server/Mieru/" + action
	q := endpoint.Query()
	q.Set("node_id", strconv.Itoa(p.NodeID))
	endpoint.RawQuery = q.Encode()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	// Never forward credentials to redirects, including a redirected HTTP URL.
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := copyClient.Do(req)
	if err != nil {
		return errors.New("panel request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("panel returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 8<<20))
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid panel JSON")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("trailing panel data")
	}
	return nil
}

func (p *Panel) Snapshot(ctx context.Context) (Snapshot, error) {
	var s Snapshot
	if err := p.request(ctx, http.MethodGet, "snapshot", nil, &s); err != nil {
		return s, err
	}
	return s, s.Validate()
}

func (p *Panel) Report(ctx context.Context, r Report) error {
	var response struct {
		Accepted bool `json:"accepted"`
	}
	if err := p.request(ctx, http.MethodPost, "traffic", r, &response); err != nil {
		return err
	}
	if !response.Accepted {
		return errors.New("traffic not acknowledged")
	}
	return nil
}
