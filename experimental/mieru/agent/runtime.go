package agent

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	mlog "github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/metrics"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"github.com/enfein/mieru/v3/pkg/socks5"
	"google.golang.org/protobuf/proto"
)

// Runtime is private to one standalone adapter process, never the legacy core.
type Runtime struct {
	allowLoopback bool // Set only by in-package integration tests.
	mux           *protocol.Mux
	mu            sync.Mutex
	connections   map[net.Conn]bool
	closing       bool
	accepted      chan struct{}
	workers       sync.WaitGroup
}

func (r *Runtime) Start(s Snapshot) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if r.mux != nil {
		return errors.New("runtime already started")
	}
	if len(s.Users) == 0 {
		return nil
	}
	mlog.SetFormatter(&mlog.NilFormatter{})
	users := make([]*pb.User, 0, len(s.Users))
	for _, u := range s.Users {
		users = append(users, &pb.User{Name: proto.String(u.Name), Password: proto.String(u.Password)})
	}
	bindings := []*pb.PortBinding{{Port: proto.Int32(int32(s.Port)), Protocol: pb.TransportProtocol_TCP.Enum()}}
	endpoints, err := appctlcommon.AddrPortToUnderlayProperties(s.ListenIP, bindings, 1400)
	if err != nil {
		return err
	}
	mapped := appctlcommon.UserListToMap(users)
	handler, err := socks5.New(&socks5.Config{AuthOpts: socks5.Auth{ClientSideAuthentication: true}, Users: mapped, Resolver: &net.Resolver{}, HandshakeTimeout: 5 * time.Second, AllowLoopbackDestination: r.allowLoopback})
	if err != nil {
		return err
	}
	mux := protocol.NewMux(false).SetServerUsers(mapped).SetEndpoints(endpoints)
	if err = mux.Start(); err != nil {
		mux.Close()
		return errors.New("Mieru listener failed")
	}
	r.mux, r.connections, r.accepted, r.closing = mux, map[net.Conn]bool{}, make(chan struct{}), false
	go r.serve(handler, mux)
	return nil
}

func (r *Runtime) serve(handler *socks5.Server, mux *protocol.Mux) {
	defer close(r.accepted)
	for {
		conn, err := mux.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.closing {
			r.mu.Unlock()
			conn.Close()
			return
		}
		r.connections[conn] = true
		r.workers.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.workers.Done()
			_ = handler.ServeConn(conn)
			r.mu.Lock()
			delete(r.connections, conn)
			r.mu.Unlock()
		}()
	}
}

func (r *Runtime) Stop() {
	if r.mux == nil {
		return
	}
	r.mu.Lock()
	r.closing = true
	for conn := range r.connections {
		_ = conn.Close()
	}
	r.mu.Unlock()
	r.mux.Close()
	<-r.accepted
	r.workers.Wait()
	r.mux = nil
}

func (r *Runtime) Metrics() (map[string]Counter, error) {
	if r.mux != nil {
		select {
		case <-r.accepted:
			return nil, errors.New("Mieru accept loop stopped")
		default:
		}
	}
	raw, err := metrics.GetMetricsAsJSON()
	if err != nil {
		return nil, err
	}
	var response struct {
		Users map[string]struct {
			Upload   int64 `json:"UploadBytes"`
			Download int64 `json:"DownloadBytes"`
		} `json:"users"`
	}
	if err = json.Unmarshal(raw, &response); err != nil {
		return nil, err
	}
	counters := map[string]Counter{}
	for name, c := range response.Users {
		counters[name] = Counter{Upload: c.Upload, Download: c.Download}
	}
	return counters, nil
}
