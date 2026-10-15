package agent

import (
	"context"
	"errors"
	"math"
	"reflect"
)

type Proxy interface {
	Start(Snapshot) error
	Stop()
	Metrics() (map[string]Counter, error)
}

type API interface {
	Snapshot(context.Context) (Snapshot, error)
	Report(context.Context, Report) error
}

type Engine struct {
	Proxy   Proxy
	API     API
	State   *State
	Save    func(*State) error
	current *Snapshot
	raw     map[string]Counter
}

func (e *Engine) sample() error {
	counters, err := e.Proxy.Metrics()
	if err != nil {
		return err
	}
	if e.raw == nil {
		e.raw = map[string]Counter{}
	}
	for name, c := range counters {
		id, ok := e.State.Names[name]
		if !ok {
			return errors.New("unknown Mieru metric owner")
		}
		old := e.raw[name]
		du, dd := c.Upload-old.Upload, c.Download-old.Download
		total := e.State.Totals[id]
		if du < 0 || dd < 0 || total.Upload > math.MaxInt64-du || total.Download > math.MaxInt64-dd {
			return errors.New("invalid traffic counter")
		}
		total.ID, total.Upload, total.Download = id, total.Upload+du, total.Download+dd
		e.State.Totals[id], e.raw[name] = total, c
	}
	return e.Save(e.State)
}

func (e *Engine) Step(ctx context.Context) (result error) {
	defer func() {
		if result != nil {
			e.Proxy.Stop()
			e.current = nil
			// Preserve traffic from sessions closed after the failed request.
			_ = e.sample()
		}
	}()
	if err := e.sample(); err != nil {
		return err
	}
	if err := e.API.Report(ctx, e.State.Report()); err != nil {
		return err
	}
	s, err := e.API.Snapshot(ctx)
	if err != nil {
		return err
	}
	if err = s.Validate(); err != nil {
		return err
	}
	if e.current != nil && reflect.DeepEqual(*e.current, s) {
		return nil
	}
	// Replacing the runtime closes established sessions as well as listeners.
	e.Proxy.Stop()
	e.current = nil
	if err = e.sample(); err != nil {
		return err
	}
	if err = e.API.Report(ctx, e.State.Report()); err != nil {
		return err
	}
	for _, u := range s.Users {
		if id, ok := e.State.Names[u.Name]; ok && id != u.ID {
			return errors.New("credential owner changed")
		}
		e.State.Names[u.Name] = u.ID
	}
	if err = e.Save(e.State); err != nil {
		return err
	}
	if err = e.Proxy.Start(s); err != nil {
		return err
	}
	e.current = &s
	return nil
}

func (e *Engine) Stop(ctx context.Context) error {
	e.Proxy.Stop()
	e.current = nil
	if err := e.sample(); err != nil {
		return err
	}
	return e.API.Report(ctx, e.State.Report())
}
