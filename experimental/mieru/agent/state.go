package agent

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

type State struct {
	Version int             `json:"version"`
	AgentID string          `json:"agent_id"`
	Names   map[string]int  `json:"names"`
	Totals  map[int]Counter `json:"totals"`
}

func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		var b [16]byte
		if _, err = rand.Read(b[:]); err != nil {
			return nil, err
		}
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		s := &State{Version: 1, AgentID: fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), Names: map[string]int{}, Totals: map[int]Counter{}}
		return s, SaveState(path, s)
	}
	if err != nil {
		return nil, err
	}
	var s State
	if json.Unmarshal(raw, &s) != nil || s.Version != 1 || !uuidPattern.MatchString(s.AgentID) || s.Names == nil || s.Totals == nil {
		return nil, errors.New("invalid state; refusing to reset accounting")
	}
	for id, c := range s.Totals {
		if id != c.ID || id < 1 || c.Upload < 0 || c.Download < 0 {
			return nil, errors.New("invalid stored counter")
		}
	}
	for name, id := range s.Names {
		if len(name) != 33 || name[0] != 'u' || id < 1 {
			return nil, errors.New("invalid stored credential owner")
		}
	}
	return &s, nil
}

func SaveState(path string, s *State) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mieru-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Sync()
	}
	return nil
}

func (s *State) Report() Report {
	r := Report{AgentID: s.AgentID, Counters: []Counter{}}
	for _, c := range s.Totals {
		r.Counters = append(r.Counters, c)
	}
	sort.Slice(r.Counters, func(i, j int) bool { return r.Counters[i].ID < r.Counters[j].ID })
	return r
}
