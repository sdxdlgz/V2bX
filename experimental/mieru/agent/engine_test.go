package agent

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

const testPassword = "11111111-2222-4333-8444-555555555555"
const testName = "u11111111222243338444555555555555"

func testSnapshot() Snapshot {
	return Snapshot{Version: 1, ListenIP: "127.0.0.1", Port: 16201, Users: []User{{ID: 1, Name: testName, Password: testPassword}}}
}

type fakeProxy struct {
	samples       map[string]Counter
	starts, stops int
}

func (p *fakeProxy) Start(Snapshot) error                 { p.starts++; return nil }
func (p *fakeProxy) Stop()                                { p.stops++ }
func (p *fakeProxy) Metrics() (map[string]Counter, error) { return p.samples, nil }

type fakeAPI struct {
	snapshot Snapshot
	fail     bool
	reports  []Report
}

func (a *fakeAPI) Snapshot(context.Context) (Snapshot, error) { return a.snapshot, nil }
func (a *fakeAPI) Report(_ context.Context, r Report) error {
	a.reports = append(a.reports, r)
	if a.fail {
		return errors.New("lost response")
	}
	return nil
}

func TestRetryRestartAndEmptyList(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.json")
	state, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	proxy, api := &fakeProxy{}, &fakeAPI{snapshot: testSnapshot()}
	engine := &Engine{Proxy: proxy, API: api, State: state, Save: func(s *State) error { return SaveState(path, s) }}
	if err = engine.Step(ctx); err != nil {
		t.Fatal(err)
	}
	proxy.samples = map[string]Counter{testName: {Upload: 100, Download: 200}}
	api.fail = true
	previousStops := proxy.stops
	if engine.Step(ctx) == nil {
		t.Fatal("unacknowledged traffic accepted")
	}
	if proxy.stops == previousStops || engine.current != nil {
		t.Fatal("failed synchronization left the proxy authorized")
	}
	// The durable report survives both a lost response and process restart.
	restored, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Report().Counters[0].Upload != 100 {
		t.Fatal("pending traffic lost")
	}
	api.fail = false
	restarted := &Engine{Proxy: &fakeProxy{}, API: api, State: restored, Save: func(s *State) error { return SaveState(path, s) }}
	if err = restarted.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if api.reports[len(api.reports)-1].Counters[0].Download != 200 {
		t.Fatal("restart changed cumulative report")
	}
	api.snapshot.Users = []User{}
	if err = restarted.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if len(restarted.current.Users) != 0 {
		t.Fatal("empty list did not revoke users")
	}
}

func TestInvalidSnapshotsCannotStart(t *testing.T) {
	for _, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.Users = nil }, func(s *Snapshot) { s.Port = 0 },
		func(s *Snapshot) { s.Users = append(s.Users, s.Users[0]) }, func(s *Snapshot) { s.Users[0].Name = "other" },
	} {
		s := testSnapshot()
		mutate(&s)
		if s.Validate() == nil {
			t.Fatal("malformed snapshot accepted")
		}
	}
}

func TestCorruptStateAndPersistenceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	proxy, api := &fakeProxy{}, &fakeAPI{snapshot: testSnapshot()}
	e := &Engine{Proxy: proxy, API: api, State: s, Save: func(*State) error { return errors.New("disk full") }}
	if e.Step(context.Background()) == nil || proxy.starts != 0 {
		t.Fatal("started without durable state")
	}
	s.AgentID = "corrupt"
	if err := SaveState(path, s); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("silently reset corrupt state")
	}
}
