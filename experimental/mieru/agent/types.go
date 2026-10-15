package agent

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

type User struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type Snapshot struct {
	Version  int    `json:"version"`
	ListenIP string `json:"listen_ip"`
	Port     int    `json:"port"`
	Users    []User `json:"users"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (s Snapshot) Validate() error {
	if s.Version != 1 || net.ParseIP(s.ListenIP) == nil || s.Port < 1 || s.Port > 65535 || s.Users == nil || len(s.Users) > 10000 {
		return errors.New("invalid snapshot header or user list")
	}
	ids, names := map[int]bool{}, map[string]bool{}
	for _, u := range s.Users {
		if u.ID < 1 || !uuidPattern.MatchString(u.Password) || u.Name != "u"+strings.ReplaceAll(u.Password, "-", "") || ids[u.ID] || names[u.Name] {
			return errors.New("invalid or duplicate user")
		}
		ids[u.ID], names[u.Name] = true, true
	}
	return nil
}

type Counter struct {
	ID       int   `json:"id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type Report struct {
	AgentID  string    `json:"agent_id"`
	Counters []Counter `json:"counters"`
}
