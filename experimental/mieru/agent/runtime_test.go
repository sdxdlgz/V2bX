package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	apiclient "github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

func realClient(t *testing.T, port int, password string) apiclient.Client {
	t.Helper()
	c := apiclient.NewClient()
	err := c.Store(&apiclient.ClientConfig{Profile: &pb.ClientProfile{
		ProfileName: proto.String("integration"), User: &pb.User{Name: proto.String(testName), Password: proto.String(password)},
		Servers: []*pb.ServerEndpoint{{IpAddress: proto.String("127.0.0.1"), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(port)), Protocol: pb.TransportProtocol_TCP.Enum()}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Stop() })
	return c
}

func TestOfficialSDKTrafficAccountingAndRevocation(t *testing.T) {
	// No external VPS, firewall, credentials or Internet endpoint is used.
	portListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	portListener.Close()
	snapshot := testSnapshot()
	snapshot.Port = port
	state, err := LoadState(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{allowLoopback: true}
	api := &fakeAPI{snapshot: snapshot}
	engine := &Engine{Proxy: runtime, API: api, State: state, Save: func(*State) error { return nil }}
	defer runtime.Stop()
	if err = engine.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("mieru verified ", 1024)))
	}))
	defer server.Close()
	destination, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	client := realClient(t, port, testPassword)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return client.DialContext(ctx, destination) }}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := httpClient.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || len(body) != 15*1024 {
		t.Fatalf("HTTP payload: bytes=%d error=%v", len(body), err)
	}

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 2048)
		n, peer, err := udp.ReadFrom(buffer)
		if err == nil {
			udp.WriteTo(buffer[:n], peer)
		}
	}()
	udpConn, err := client.DialContext(context.Background(), udp.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	packets := apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(udpConn))
	defer packets.Close()
	packets.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = packets.WriteTo([]byte("UDP verified"), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, _, err := packets.ReadFrom(buffer)
	if err != nil || string(buffer[:n]) != "UDP verified" {
		t.Fatalf("UDP echo: %q error=%v", buffer[:n], err)
	}

	// A held authenticated connection must become unusable after an empty list.
	held, err := client.DialContext(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err = engine.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	totals := state.Totals[1]
	if totals.Upload <= 0 || totals.Download < int64(len(body)) {
		t.Fatalf("bad directional counters: %+v", totals)
	}
	t.Logf("official SDK TCP+UDP passed; accounted upload=%d download=%d", totals.Upload, totals.Download)
	if binary := os.Getenv("MIERU_TEST_MIHOMO"); binary != "" {
		testMihomo(t, binary, port, server.URL)
		if err = engine.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		if state.Totals[1].Download < totals.Download+int64(len(body)) {
			t.Fatal("Mihomo traffic bypassed Mieru accounting")
		}
	}
	api.snapshot.Users = []User{}
	if err = engine.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	held.SetDeadline(time.Now().Add(2 * time.Second))
	_, writeErr := held.Write([]byte("GET / HTTP/1.1\r\nHost: local\r\n\r\n"))
	if writeErr == nil {
		_, err = held.Read(buffer)
		if err == nil {
			t.Fatal("revoked session still carries traffic")
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("empty user list left listener running")
	}
}

func testMihomo(t *testing.T, binary string, port int, target string) {
	t.Helper()
	dir := t.TempDir()
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := local.Addr().(*net.TCPAddr).Port
	local.Close()
	profile := map[string]any{"name": "Mieru integration", "type": "mieru", "server": "127.0.0.1", "port": port, "transport": "TCP", "username": testName, "password": testPassword, "udp": true}
	if fixture := os.Getenv("MIERU_TEST_PROFILE"); fixture != "" {
		raw, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, &profile); err != nil {
			t.Fatal(err)
		}
		profile["server"], profile["port"] = "127.0.0.1", port
	}
	config := map[string]any{"mixed-port": proxyPort, "allow-lan": false, "mode": "rule", "log-level": "debug",
		"proxies": []any{profile}, "proxy-groups": []any{map[string]any{"name": "PROXY", "type": "select", "proxies": []string{profile["name"].(string)}}}, "rules": []string{"MATCH,PROXY"}}
	raw, _ := json.Marshal(config)
	path := filepath.Join(dir, "config.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	process := exec.Command(binary, "-d", dir, "-f", path)
	logPath := filepath.Join(dir, "mihomo.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	process.Stdout, process.Stderr = logFile, logFile
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { process.Process.Kill(); process.Wait() }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort))
	var status int
	var body []byte
	// Mihomo binds the listener before its providers and tunnel are ready.
	// Probe the complete path instead of treating a listening port as readiness.
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		status, body, err = fetchThroughProxy(address, target)
		if err == nil && status == http.StatusOK {
			break
		}
	}
	if err != nil || status != http.StatusOK || len(body) != 15*1024 {
		logs, _ := os.ReadFile(logPath)
		t.Fatalf("Mihomo fetch failed: status=%d bytes=%d error=%v; log: %s", status, len(body), err, logs)
	}
	t.Log("Mihomo 1.19.32 consumed Mieru profile and proxied HTTP successfully")
}

func fetchThroughProxy(address, target string) (int, []byte, error) {
	conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target, strings.TrimPrefix(target, "http://"))
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	return response.StatusCode, body, err
}
