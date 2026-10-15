package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var errRevoked = errors.New("gateway authorization revoked")

func panelRequest(ctx context.Context, c Config, action string, body any) ([]byte, error) {
	method := http.MethodGet
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, errors.New("invalid report")
		}
		reader = bytes.NewReader(data)
		method = http.MethodPost
	}
	endpoint := strings.TrimRight(c.PanelURL, "/") + "/api/v1/server/Upstream/" + action + "?id=" + strconv.Itoa(c.UpstreamID)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, errors.New("invalid panel endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("panel unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 404 {
		return nil, errRevoked
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("panel rejected request")
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65536))
}

func snapshot(ctx context.Context, c Config) (Snapshot, error) {
	var response struct {
		Data Snapshot `json:"data"`
	}
	data, err := panelRequest(ctx, c, "config", nil)
	if err != nil {
		return response.Data, err
	}
	if json.Unmarshal(data, &response) != nil {
		return response.Data, errors.New("invalid panel response")
	}
	s := response.Data
	if s.ID != c.UpstreamID || s.Revision < 1 || s.RefreshInterval < 300 || s.RefreshInterval > 86400 {
		return s, errors.New("invalid panel snapshot")
	}
	return s, nil
}
