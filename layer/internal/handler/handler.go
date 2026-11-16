// Package handler answers the device's requests to the layer, as
// spec/asyncapi-layer.yaml of the Imatra server describes them: the
// certificate for its deployment (cred) and the TLS signature (sign).
package handler

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/Chargetronic/imatra.test_harness/layer/internal/pki"
	"github.com/Chargetronic/imatra.test_harness/layer/internal/store"
)

const (
	CertTTL       = 7 * 24 * time.Hour
	CertsPerDay   = 8
	SignsPerMin   = 20
	SignAlgorithm = "ecdsa-p256-sha256"
)

// --- certificate for the deployment

type CredRequest struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	CSR        string `json:"csr"`
	BindingVer int64  `json:"binding_ver"`
}

type CredResponse struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	CloudID    string `json:"cloud_id,omitempty"`
	Address    string `json:"address,omitempty"`
	BindingVer int64  `json:"binding_ver,omitempty"`
	CA         string `json:"ca,omitempty"`
	Cert       string `json:"cert,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	NextReq    string `json:"next_req,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Cred issues certificates under the roots of the deployments.
type Cred struct {
	Store store.Store
	Roots func(deployment string) (*pki.Authority, error)
	Now   func() time.Time
}

// Handle answers one request; ok=false: unparseable, no answer.
func (c *Cred) Handle(device string, payload []byte) (CredResponse, bool) {
	var q CredRequest
	if err := json.Unmarshal(payload, &q); err != nil || q.ID == "" || len(q.ID) > 64 {
		return CredResponse{}, false
	}
	now := c.Now()
	res := CredResponse{V: 1, ID: q.ID}
	err := c.Store.Update(func(st *store.State) error {
		d := st.Devices[device]
		switch {
		case d == nil:
			res.Error = "unknown device"
			return nil
		case d.Status != "active":
			res.Error = "revoked"
			return nil
		case d.Deployment == "":
			res.Error = "unbound"
			return nil
		}
		dep := st.Deployments[d.Deployment]
		if dep == nil {
			res.Error = "cloud disabled"
			return nil
		}
		root, err := c.Roots(d.Deployment)
		if err != nil {
			res.Error = "no cloud ca"
			return nil
		}
		_, pub, err := pki.ParseCSR([]byte(q.CSR))
		if err != nil {
			res.Error = "bad csr"
			return nil
		}
		if pki.SPKI(pub) != d.SPKI {
			res.Error = "key mismatch"
			return nil
		}
		recent := d.Issued[:0]
		for _, t := range d.Issued {
			if now.Sub(t) < 24*time.Hour {
				recent = append(recent, t)
			}
		}
		d.Issued = recent
		if len(d.Issued) >= CertsPerDay {
			res.Error = "rate limit"
			return nil
		}
		certPEM, cert, err := root.Issue(device, "", pub, CertTTL, pki.Client)
		if err != nil {
			res.Error = "bad csr"
			return nil
		}
		d.Issued = append(d.Issued, now)
		res.CloudID, res.Address, res.BindingVer = d.Deployment, dep.Address, d.BindingVer
		res.CA, res.Cert = string(root.PEM), string(certPEM)
		res.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
		res.NextReq = now.Add(24 * time.Hour).UTC().Format(time.RFC3339) // fixed (no operator change here)
		return nil
	})
	if err != nil {
		res = CredResponse{V: 1, ID: q.ID, Error: "registry unavailable"}
	}
	return res, true
}

// --- TLS signature

type SignRequest struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Alg    string `json:"alg"`
	Digest string `json:"digest"`
}

type SignResponse struct {
	V     int    `json:"v"`
	ID    string `json:"id"`
	Sig   string `json:"sig,omitempty"`
	Error string `json:"error,omitempty"`
}

// Sign signs with the test SECC key only (TK-5).
type Sign struct {
	Key    *ecdsa.PrivateKey // nil: "no key"
	Status func(device string) (string, error)
	Now    func() time.Time
	mu     sync.Mutex
	recent map[string][]time.Time
}

func (s *Sign) allow(device string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recent == nil {
		s.recent = map[string][]time.Time{}
	}
	var w []time.Time
	for _, t := range s.recent[device] {
		if now.Sub(t) < time.Minute {
			w = append(w, t)
		}
	}
	if len(w) >= SignsPerMin {
		s.recent[device] = w
		return false
	}
	s.recent[device] = append(w, now)
	return true
}

// Handle answers one request; ok=false: unparseable, no answer.
func (s *Sign) Handle(device string, payload []byte) (SignResponse, bool) {
	var q SignRequest
	if err := json.Unmarshal(payload, &q); err != nil || q.ID == "" {
		return SignResponse{}, false
	}
	res := SignResponse{V: 1, ID: q.ID}
	refuse := func(why string) (SignResponse, bool) { res.Error = why; return res, true }
	if s.Key == nil {
		return refuse("no key")
	}
	switch st, err := s.Status(device); {
	case err != nil:
		return refuse("registry unavailable")
	case st == "":
		return refuse("unknown device")
	case st != "active":
		return refuse("revoked")
	}
	if !s.allow(device, s.Now()) {
		return refuse("rate limit")
	}
	if q.Alg != SignAlgorithm {
		return refuse("unsupported alg")
	}
	digest, err := base64.StdEncoding.DecodeString(q.Digest)
	if err != nil || len(digest) != 32 {
		return refuse("bad digest")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.Key, digest)
	if err != nil {
		return refuse("sign failed")
	}
	res.Sig = base64.StdEncoding.EncodeToString(sig)
	return res, true
}
