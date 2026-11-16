package handler

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Chargetronic/imatra.test_harness/layer/internal/pki"
	"github.com/Chargetronic/imatra.test_harness/layer/internal/store"
)

func csrFor(t *testing.T, k *ecdsa.PrivateKey) string {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

type line struct {
	Topic   string `json:"topic"`
	Payload any    `json:"payload"`
}

// Every outcome of both handlers. With CONTRACT_OUT set, the requests and
// answers are written as JSON lines for the harness checker (conformance batch).
func TestEveryOutcome(t *testing.T) {
	dir := t.TempDir()
	s := store.Store{Path: filepath.Join(dir, "registry.json")}
	root, _ := pki.NewRoot("dep")
	key, _ := pki.NewKey()
	other, _ := pki.NewKey()
	s.Update(func(st *store.State) error {
		st.Deployments["dep"] = &store.Deployment{Address: "mqtt:8883", Broker: "mqtt:8883"}
		st.Devices["dev-ok"] = &store.Device{Status: "active", SPKI: pki.SPKI(&key.PublicKey), Deployment: "dep", BindingVer: 2}
		st.Devices["dev-rev"] = &store.Device{Status: "revoked", SPKI: pki.SPKI(&key.PublicKey), Deployment: "dep"}
		st.Devices["dev-unb"] = &store.Device{Status: "active", SPKI: pki.SPKI(&key.PublicKey)}
		st.Devices["dev-gone"] = &store.Device{Status: "active", SPKI: pki.SPKI(&key.PublicKey), Deployment: "removed"}
		st.Devices["dev-noca"] = &store.Device{Status: "active", SPKI: pki.SPKI(&key.PublicKey), Deployment: "noca"}
		st.Deployments["noca"] = &store.Deployment{Address: "x:8883"}
		st.Devices["dev-lim"] = &store.Device{Status: "active", SPKI: pki.SPKI(&key.PublicKey), Deployment: "dep"}
		for i := 0; i < CertsPerDay; i++ {
			st.Devices["dev-lim"].Issued = append(st.Devices["dev-lim"].Issued, time.Now())
		}
		return nil
	})
	cred := &Cred{Store: s, Now: time.Now, Roots: func(d string) (*pki.Authority, error) {
		if d == "dep" {
			return root, nil
		}
		return nil, errors.New("no root")
	}}
	var out []line
	add := func(dev, topic string, p any) { out = append(out, line{"dev/" + dev + "/" + topic, p}) }

	good := csrFor(t, key)
	seen := map[string]bool{}
	for _, c := range []struct{ dev, csr, want string }{
		{"dev-ok", good, ""}, {"dev-x", good, "unknown device"}, {"dev-rev", good, "revoked"},
		{"dev-unb", good, "unbound"}, {"dev-gone", good, "cloud disabled"}, {"dev-noca", good, "no cloud ca"},
		{"dev-ok", "not a csr", "bad csr"}, {"dev-ok", csrFor(t, other), "key mismatch"}, {"dev-lim", good, "rate limit"},
	} {
		q := CredRequest{V: 1, ID: "c-" + c.dev, CSR: c.csr, BindingVer: 0}
		b, _ := json.Marshal(q)
		r, ok := cred.Handle(c.dev, b)
		if !ok || r.Error != c.want {
			t.Errorf("cred %s: %q, want %q", c.dev, r.Error, c.want)
		}
		seen[r.Error] = true
		add(c.dev, "cred/req", q)
		add(c.dev, "cred/res", r)
		if c.want == "" {
			blk, _ := pem.Decode([]byte(r.Cert))
			cert, err := x509.ParseCertificate(blk.Bytes)
			if err != nil || cert.Subject.CommonName != "dev-ok" {
				t.Fatalf("certificate: %v", err)
			}
			pool := x509.NewCertPool()
			pool.AddCert(root.Cert)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				t.Fatalf("not under the deployment root: %v", err)
			}
			if r.CloudID != "dep" || r.Address != "mqtt:8883" || r.BindingVer != 2 || r.NextReq == "" {
				t.Fatalf("binding: %+v", r)
			}
		}
	}
	if _, ok := cred.Handle("dev-ok", []byte("{")); ok {
		t.Error("garbage answered")
	}

	k, _ := pki.NewKey()
	sign := &Sign{Key: k, Now: time.Now, Status: func(d string) (string, error) {
		switch d {
		case "dev-ok":
			return "active", nil
		case "dev-rev":
			return "revoked", nil
		case "dev-db":
			return "", errors.New("down")
		}
		return "", nil
	}}
	d := sha256.Sum256([]byte("ServerKeyExchange"))
	dig := base64.StdEncoding.EncodeToString(d[:])
	for i, c := range []struct{ dev, alg, dig, want string }{
		{"dev-ok", SignAlgorithm, dig, ""}, {"dev-x", SignAlgorithm, dig, "unknown device"},
		{"dev-rev", SignAlgorithm, dig, "revoked"}, {"dev-db", SignAlgorithm, dig, "registry unavailable"},
		{"dev-ok", "rsa", dig, "unsupported alg"}, {"dev-ok", SignAlgorithm, "AAAA", "bad digest"},
	} {
		q := SignRequest{V: 1, ID: string(rune('a' + i)), Alg: c.alg, Digest: c.dig}
		b, _ := json.Marshal(q)
		r, _ := sign.Handle(c.dev, b)
		if r.Error != c.want {
			t.Errorf("sign %s/%s: %q, want %q", c.dev, c.alg, r.Error, c.want)
		}
		if c.want == "" {
			sig, _ := base64.StdEncoding.DecodeString(r.Sig)
			if !ecdsa.VerifyASN1(&k.PublicKey, d[:], sig) {
				t.Fatal("signature does not verify")
			}
		}
		if c.alg == SignAlgorithm && c.dig == dig {
			add(c.dev, "sign/req", q)
		}
		add(c.dev, "sign/res", r)
	}
	for i := 0; i < SignsPerMin; i++ {
		b, _ := json.Marshal(SignRequest{V: 1, ID: "r", Alg: SignAlgorithm, Digest: dig})
		if r, _ := sign.Handle("dev-ok", b); r.Error == "rate limit" {
			add("dev-ok", "sign/res", r)
			goto limited
		}
	}
	t.Error("no rate limit")
limited:
	if r, _ := (&Sign{Status: sign.Status, Now: time.Now}).Handle("dev-ok", []byte(`{"v":1,"id":"n","alg":"ecdsa-p256-sha256","digest":"`+dig+`"}`)); r.Error != "no key" {
		t.Errorf("no key: %q", r.Error)
	} else {
		add("dev-ok", "sign/res", r)
	}

	if p := os.Getenv("CONTRACT_OUT"); p != "" {
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, l := range out {
			enc.Encode(l)
		}
	}
}

func TestRegistryMessages(t *testing.T) {
	st := &store.State{Devices: map[string]*store.Device{
		"a": {Status: "active", Deployment: "dep", BindingVer: 3, Type: "station", Rules: json.RawMessage(`{"topology":"integrated"}`)},
		"b": {Status: "revoked", BindingVer: 4},
	}, Deployments: map[string]*store.Deployment{"dep": {}}}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	st.Queue("dep", "a", "bound", now)
	st.Queue("dep", "b", "revoked", now)
	var m map[string]any
	json.Unmarshal(st.Outbox[0].Payload, &m)
	if m["state"] != "bound" || m["type"] != "station" || m["tz"] != "UTC" || st.Outbox[0].Topic != "registry/dev/a" {
		t.Fatalf("bound: %v", m)
	}
	m = map[string]any{}
	json.Unmarshal(st.Outbox[1].Payload, &m)
	if _, ok := m["rules"]; ok {
		t.Fatalf("revoked carries rules: %v", m)
	}
	m = map[string]any{}
	json.Unmarshal(st.Digest("dep", now), &m)
	if m["bound"].(float64) != 1 || m["max_binding_ver"].(float64) != 4 {
		t.Fatalf("digest: %v", m)
	}
	if p := os.Getenv("CONTRACT_OUT"); p != "" {
		f, _ := os.OpenFile(p+".registry", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		defer f.Close()
		enc := json.NewEncoder(f)
		for _, o := range st.Outbox {
			enc.Encode(line{o.Topic, o.Payload})
		}
		enc.Encode(line{"registry/digest", st.Digest("dep", now)})
	}
}
