package main

import (
	"io"
	"net"
	"sync"
	"time"
)

// A stable loopback endpoint keeps V2bX configuration independent of core updates.
// SOCKS UDP association replies carry the selected core's own loopback UDP port.
type Relay struct {
	mu          sync.Mutex
	target      string
	connections map[net.Conn]struct{}
	listener    net.Listener
}

func newRelay(address string) (*Relay, error) {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	r := &Relay{listener: l, connections: map[net.Conn]struct{}{}}
	go r.accept()
	return r, nil
}

func (r *Relay) set(target string, revoke bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.target = target
	if revoke {
		for conn := range r.connections {
			_ = conn.Close()
		}
	}
}

func (r *Relay) accept() {
	for {
		client, err := r.listener.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		target := r.target
		if target != "" {
			r.connections[client] = struct{}{}
		}
		r.mu.Unlock()
		if target == "" {
			_ = client.Close()
			continue
		}
		go r.forward(client, target)
	}
}

func (r *Relay) forward(client net.Conn, target string) {
	defer client.Close()
	defer func() { r.mu.Lock(); delete(r.connections, client); r.mu.Unlock() }()
	server, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer server.Close()
	r.mu.Lock()
	if r.target == "" {
		r.mu.Unlock()
		return
	}
	r.connections[server] = struct{}{}
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.connections, server); r.mu.Unlock() }()
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(server, client)
		if c, ok := server.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}()
	_, _ = io.Copy(client, server)
	_ = client.Close()
	_ = server.Close()
	<-done
}

func (r *Relay) close() { r.set("", true); _ = r.listener.Close() }
