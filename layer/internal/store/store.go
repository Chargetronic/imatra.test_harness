// Package store keeps the test layer's registry in one JSON file. The
// commands (provision, bind, ...) and the running service share it under a
// file lock; the service publishes what the commands queue.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type Device struct {
	Status     string          `json:"status"` // active | revoked
	SPKI       string          `json:"spki"`   // the device key, pinned at provisioning
	Deployment string          `json:"deployment,omitempty"`
	BindingVer int64           `json:"binding_ver"`
	Type       string          `json:"type,omitempty"`
	Rules      json.RawMessage `json:"rules,omitempty"`
	Issued     []time.Time     `json:"issued,omitempty"` // certificates of the last 24 h
}

type Deployment struct {
	Address string `json:"address"` // host:port the devices connect to
	Broker  string `json:"broker"`  // host:port the layer publishes the registry to
}

// Message: a registry message waiting for its deployment.
type Message struct {
	Deployment string          `json:"deployment"`
	Topic      string          `json:"topic"`
	Payload    json.RawMessage `json:"payload"`
}

type State struct {
	Devices     map[string]*Device     `json:"devices"`
	Deployments map[string]*Deployment `json:"deployments"`
	Outbox      []Message              `json:"outbox"`
}

// Store is the file and its lock.
type Store struct{ Path string }

func (s Store) lock() (*os.File, error) {
	f, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (s Store) read() (*State, error) {
	st := &State{Devices: map[string]*Device{}, Deployments: map[string]*Deployment{}}
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, err
	}
	if st.Devices == nil {
		st.Devices = map[string]*Device{}
	}
	if st.Deployments == nil {
		st.Deployments = map[string]*Deployment{}
	}
	return st, nil
}

// Update runs f on the state under the lock and writes it back if f returns nil.
func (s Store) Update(f func(*State) error) error {
	l, err := s.lock()
	if err != nil {
		return err
	}
	defer l.Close()
	st, err := s.read()
	if err != nil {
		return err
	}
	if err := f(st); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// View runs f on a copy of the state under the lock.
func (s Store) View(f func(*State) error) error {
	l, err := s.lock()
	if err != nil {
		return err
	}
	defer l.Close()
	st, err := s.read()
	if err != nil {
		return err
	}
	return f(st)
}

// RegistryEntry is the registry message for one device (spec/asyncapi-registry.yaml).
func RegistryEntry(id string, d *Device, state string, at time.Time) json.RawMessage {
	m := map[string]any{"v": 1, "device_id": id, "state": state, "binding_ver": d.BindingVer,
		"at": at.UTC().Format(time.RFC3339)}
	if state == "bound" {
		// fixed data behind the contract (TK-12): no real location or zone
		m["lat"], m["lon"], m["tz"] = 0.0, 0.0, "UTC"
		if d.Type != "" {
			m["type"] = d.Type
		}
		if len(d.Rules) > 0 {
			m["rules"] = d.Rules
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// Queue puts the device's current registry message for dep in the outbox.
func (st *State) Queue(dep, id, state string, now time.Time) {
	d := st.Devices[id]
	st.Outbox = append(st.Outbox, Message{Deployment: dep, Topic: "registry/dev/" + id,
		Payload: RegistryEntry(id, d, state, now)})
}

// Digest is the daily reconciliation message for one deployment.
func (st *State) Digest(dep string, now time.Time) json.RawMessage {
	var n int
	var max int64
	for _, d := range st.Devices {
		if d.Deployment == dep && d.Status == "active" {
			n++
		}
		if d.BindingVer > max {
			max = d.BindingVer
		}
	}
	b, _ := json.Marshal(map[string]any{"v": 1, "bound": n, "max_binding_ver": max, "at": now.UTC().Format(time.RFC3339)})
	return b
}
