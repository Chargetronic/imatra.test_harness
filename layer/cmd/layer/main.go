// layer: the test service layer of the Imatra test harness.
//
//	layer init                          create every trust root and certificate (never replaces a root)
//	layer provision ID                  new test station: key, certificate, bootstrap package on stdout
//	layer bind ID [DEPLOYMENT]          bind (default deployment: the first one); immediate
//	layer unbind ID | revoke ID         immediate
//	layer type ID TYPE | rules ID JSON  registry fields
//	layer list                          devices and deployments
//	layer fleet OP PREFIX FROM TO [DEP] many devices at once, ids PREFIX%05d (as fleetgen):
//	                                    add (register and bind), bind, unbind, revoke;
//	                                    one write of the registry (load tests)
//	layer serve                         answer cred/sign requests, publish the registry
//
// Settings (environment): LAYER_DIR (/data), LAYER_BROKER (layer-mqtt:8883),
// DEPLOYMENT (test-deployment), DEPLOYMENT_ADDRESS (address the devices use,
// mqtt:8883), DEPLOYMENT_BROKER (where the registry goes, mqtt:8883),
// DEPLOYMENT_DNS (names in the deployment broker certificate, comma-separated, mqtt).
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/Chargetronic/imatra.test_harness/layer/internal/handler"
	"github.com/Chargetronic/imatra.test_harness/layer/internal/pki"
	"github.com/Chargetronic/imatra.test_harness/layer/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var (
	dir        = env("LAYER_DIR", "/data")
	pkiDir     = filepath.Join(dir, "pki")
	st         = store.Store{Path: filepath.Join(dir, "registry.json")}
	layerAddr  = env("LAYER_BROKER", "layer-mqtt:8883")
	deployment = env("DEPLOYMENT", "test-deployment")
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	a := os.Args[2:]
	need := func(n int) {
		if len(a) < n {
			usage()
		}
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initPKI()
	case "provision":
		need(1)
		err = provision(a[0])
	case "bind":
		need(1)
		dep := deployment
		if len(a) > 1 {
			dep = a[1]
		}
		err = bind(a[0], dep)
	case "unbind":
		need(1)
		err = change(a[0], func(st *store.State, d *store.Device, now time.Time) error {
			if d.Deployment == "" {
				return errors.New("not bound")
			}
			d.BindingVer++
			st.Queue(d.Deployment, a[0], "unbound", now)
			d.Deployment = ""
			return nil
		})
	case "revoke":
		need(1)
		err = change(a[0], func(st *store.State, d *store.Device, now time.Time) error {
			d.Status = "revoked"
			d.BindingVer++
			if d.Deployment != "" {
				st.Queue(d.Deployment, a[0], "revoked", now)
			}
			return nil
		})
	case "type":
		need(2)
		err = change(a[0], func(st *store.State, d *store.Device, now time.Time) error {
			d.Type = a[1]
			return requeue(st, a[0], d, now)
		})
	case "rules":
		need(2)
		if !json.Valid([]byte(a[1])) || !strings.HasPrefix(strings.TrimSpace(a[1]), "{") {
			log.Fatal("rules: a JSON object")
		}
		err = change(a[0], func(st *store.State, d *store.Device, now time.Time) error {
			d.Rules = json.RawMessage(a[1])
			return requeue(st, a[0], d, now)
		})
	case "list":
		err = list()
	case "fleet":
		need(4)
		dep := deployment
		if len(a) > 4 {
			dep = a[4]
		}
		err = fleet(a[0], a[1], a[2], a[3], dep)
	case "serve":
		err = serve()
	default:
		usage()
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	log.Fatal(`usage: layer init | provision ID | bind ID [DEPLOYMENT] | unbind ID | revoke ID |
       type ID TYPE | rules ID JSON | list | fleet OP PREFIX FROM TO [DEPLOYMENT] | serve`)
}

// --- trust roots

func ensureRoot(name, cn string) (*pki.Authority, error) {
	if pki.Exists(pkiDir, name) {
		return pki.LoadAuthority(pkiDir, name)
	}
	a, err := pki.NewRoot(cn)
	if err != nil {
		return nil, err
	}
	log.Printf("created %s", name)
	return a, pki.Save(pkiDir, name, a.PEM, a.Key)
}

func ensureCert(a *pki.Authority, dirName, name, cn string, kind pki.Kind, names ...string) error {
	d := filepath.Join(pkiDir, dirName)
	if pki.Exists(d, name) {
		return nil
	}
	k, err := pki.NewKey()
	if err != nil {
		return err
	}
	c, _, err := a.Issue(cn, "", &k.PublicKey, 2*365*24*time.Hour, kind, names...)
	if err != nil {
		return err
	}
	return pki.Save(d, name, c, k)
}

func initPKI() error {
	layerCA, err := ensureRoot("layer-ca", "Test layer CA")
	if err != nil {
		return err
	}
	host := strings.Split(layerAddr, ":")[0]
	if err := ensureCert(layerCA, "layer-broker", "server", host, pki.Server, host, "localhost", "127.0.0.1"); err != nil {
		return err
	}
	// the layer's broker (Mosquitto, uid 1883) reads its own key
	if os.Geteuid() == 0 {
		uid := 1883
		fmt.Sscan(env("BROKER_UID", "1883"), &uid)
		for _, f := range []string{"server.crt", "server.key"} {
			if err := os.Chown(filepath.Join(pkiDir, "layer-broker", f), uid, uid); err != nil {
				return err
			}
		}
	}
	if err := ensureCert(layerCA, "service", "client", "svc-layer", pki.Client); err != nil {
		return err
	}
	v2g, err := ensureRoot("v2g-root", "Test V2G root (not for real EVs)")
	if err != nil {
		return err
	}
	if !pki.Exists(pkiDir, "secc") {
		k, _ := pki.NewKey()
		c, _, err := v2g.Issue("SECC test", "", &k.PublicKey, 2*365*24*time.Hour, pki.Leaf)
		if err != nil {
			return err
		}
		if err := pki.Save(pkiDir, "secc", c, k); err != nil {
			return err
		}
	}
	root, err := ensureRoot(filepath.Join("deployments", deployment, "ca"), "Test deployment "+deployment)
	if err != nil {
		return err
	}
	depDir := filepath.Join("deployments", deployment)
	names := strings.Split(env("DEPLOYMENT_DNS", "mqtt"), ",")
	// the files the deployment imports (Imatra: pki-init import)
	if err := ensureCert(root, filepath.Join(depDir, "for-imatra"), "broker", names[0], pki.Server, append(names, "localhost", "127.0.0.1")...); err != nil {
		return err
	}
	ca, _ := os.ReadFile(filepath.Join(pkiDir, depDir, "ca.crt"))
	if err := os.WriteFile(filepath.Join(pkiDir, depDir, "for-imatra", "ca.crt"), ca, 0o644); err != nil {
		return err
	}
	if err := ensureCert(root, depDir, "layer", "layer", pki.Client); err != nil {
		return err
	}
	return st.Update(func(s *store.State) error {
		if s.Deployments[deployment] == nil {
			s.Deployments[deployment] = &store.Deployment{
				Address: env("DEPLOYMENT_ADDRESS", "mqtt:8883"), Broker: env("DEPLOYMENT_BROKER", "mqtt:8883")}
		}
		log.Printf("trust roots ready in %s; deployment %s: import %s into Imatra",
			pkiDir, deployment, filepath.Join(pkiDir, depDir, "for-imatra"))
		return nil
	})
}

// --- devices

// Bootstrap is the package a test station starts from (layer/bootstrap.schema.json).
type Bootstrap struct {
	V        int    `json:"v"`
	DeviceID string `json:"device_id"`
	Layer    struct {
		Address string `json:"address"`
		CA      string `json:"ca"`
	} `json:"layer"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
	SECC struct {
		Chain string `json:"chain"` // the SECC certificate the station shows the EV
	} `json:"secc"`
}

func validID(id string) bool {
	if len(id) < 3 || len(id) > 63 || id == "layer" || id == "server" || strings.HasPrefix(id, "svc-") || id[0] == '-' {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func provision(id string) error {
	if !validID(id) {
		return fmt.Errorf("device id %q: lowercase letters, digits and '-', 3..63 characters; not layer, server, svc-*", id)
	}
	ca, err := pki.LoadAuthority(pkiDir, "layer-ca")
	if err != nil {
		return fmt.Errorf("run 'layer init' first: %w", err)
	}
	k, _ := pki.NewKey()
	cert, _, err := ca.Issue(id, pki.ClassBench, &k.PublicKey, 2*365*24*time.Hour, pki.Client)
	if err != nil {
		return err
	}
	secc, _ := os.ReadFile(filepath.Join(pkiDir, "secc.crt"))
	err = st.Update(func(s *store.State) error {
		if d := s.Devices[id]; d != nil {
			d.SPKI, d.Status = pki.SPKI(&k.PublicKey), "active"
			d.BindingVer++
			return nil
		}
		s.Devices[id] = &store.Device{Status: "active", SPKI: pki.SPKI(&k.PublicKey)}
		return nil
	})
	if err != nil {
		return err
	}
	b := Bootstrap{V: 1, DeviceID: id, Cert: string(cert), Key: string(pki.KeyPEM(k))}
	b.Layer.Address, b.Layer.CA = layerAddr, string(ca.PEM)
	b.SECC.Chain = string(secc)
	out, _ := json.MarshalIndent(b, "", "  ")
	fmt.Println(string(out))
	log.Printf("device %s provisioned (test certificate, software key); bind it: layer bind %s", id, id)
	return nil
}

func change(id string, f func(*store.State, *store.Device, time.Time) error) error {
	return st.Update(func(s *store.State) error {
		d := s.Devices[id]
		if d == nil {
			return fmt.Errorf("no device %s", id)
		}
		return f(s, d, time.Now())
	})
}

// requeue: a field changed; the bound deployment hears it.
func requeue(s *store.State, id string, d *store.Device, now time.Time) error {
	d.BindingVer++
	if d.Deployment != "" && d.Status == "active" {
		s.Queue(d.Deployment, id, "bound", now)
	}
	return nil
}

func bind(id, dep string) error {
	return change(id, func(s *store.State, d *store.Device, now time.Time) error {
		if s.Deployments[dep] == nil {
			return fmt.Errorf("no deployment %s", dep)
		}
		if d.Status != "active" {
			return errors.New("revoked")
		}
		if d.Deployment != "" && d.Deployment != dep {
			d.BindingVer++
			s.Queue(d.Deployment, id, "unbound", now)
		}
		d.Deployment = dep
		d.BindingVer++
		s.Queue(dep, id, "bound", now)
		return nil
	})
}

// fleet: many devices in one write of the registry (load tests). Devices added
// here have no pinned key: their certificates come from the deployment's root
// (fleetgen -client-ca), not from cred requests.
func fleet(op, prefix, from, to, dep string) error {
	a, err1 := strconv.Atoi(from)
	b, err2 := strconv.Atoi(to)
	if err1 != nil || err2 != nil || a < 0 || b < a {
		return errors.New("fleet: FROM and TO are numbers, FROM <= TO")
	}
	n := 0
	err := st.Update(func(s *store.State) error {
		if s.Deployments[dep] == nil {
			return fmt.Errorf("no deployment %s", dep)
		}
		now := time.Now()
		for i := a; i <= b; i++ {
			id := fmt.Sprintf("%s%05d", prefix, i)
			d := s.Devices[id]
			switch op {
			case "add":
				if d == nil {
					d = &store.Device{Status: "active", Type: "adapter"}
					s.Devices[id] = d
				}
				fallthrough
			case "bind":
				if d == nil || d.Status != "active" {
					continue
				}
				if d.Deployment != "" && d.Deployment != dep {
					d.BindingVer++
					s.Queue(d.Deployment, id, "unbound", now)
				}
				d.Deployment = dep
				d.BindingVer++
				s.Queue(dep, id, "bound", now)
			case "unbind":
				if d == nil || d.Deployment == "" {
					continue
				}
				d.BindingVer++
				s.Queue(d.Deployment, id, "unbound", now)
				d.Deployment = ""
			case "revoke":
				if d == nil || d.Status != "active" {
					continue
				}
				d.Status = "revoked"
				d.BindingVer++
				if d.Deployment != "" {
					s.Queue(d.Deployment, id, "revoked", now)
				}
			default:
				return errors.New("fleet: OP is add, bind, unbind or revoke")
			}
			n++
		}
		return nil
	})
	if err == nil {
		log.Printf("fleet %s: %d devices %s%05d..%s%05d", op, n, prefix, a, prefix, b)
	}
	return err
}

func list() error {
	return st.View(func(s *store.State) error {
		ids := make([]string, 0, len(s.Devices))
		for id := range s.Devices {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		fmt.Println("DEVICE\tSTATUS\tDEPLOYMENT\tBINDING_VER")
		for _, id := range ids {
			d := s.Devices[id]
			fmt.Printf("%s\t%s\t%s\t%d\n", id, d.Status, d.Deployment, d.BindingVer)
		}
		for id, dep := range s.Deployments {
			fmt.Printf("deployment %s: devices connect to %s, registry to %s\n", id, dep.Address, dep.Broker)
		}
		fmt.Printf("%d registry message(s) waiting\n", len(s.Outbox))
		return nil
	})
}

// --- service

func tlsConfig(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}, nil
}

func client(addr, id string, tc *tls.Config, onConnect mqtt.OnConnectHandler) mqtt.Client {
	o := mqtt.NewClientOptions().AddBroker("tls://" + addr).SetClientID(id).SetTLSConfig(tc).
		SetAutoReconnect(true).SetConnectRetry(true).SetConnectRetryInterval(2 * time.Second).
		SetOnConnectHandler(onConnect).
		SetConnectionLostHandler(func(_ mqtt.Client, err error) { log.Printf("%s: connection lost: %v", addr, err) })
	c := mqtt.NewClient(o)
	c.Connect()
	return c
}

func serve() error {
	if err := initPKI(); err != nil {
		return err
	}
	secc, err := pki.LoadAuthority(pkiDir, "secc")
	if err != nil {
		return err
	}
	roots := map[string]*pki.Authority{}
	cred := &handler.Cred{Store: st, Now: time.Now, Roots: func(dep string) (*pki.Authority, error) {
		if r, ok := roots[dep]; ok {
			return r, nil
		}
		r, err := pki.LoadAuthority(filepath.Join(pkiDir, "deployments", dep), "ca")
		if err == nil {
			roots[dep] = r
		}
		return r, err
	}}
	sign := &handler.Sign{Key: secc.Key, Now: time.Now, Status: func(dev string) (string, error) {
		var status string
		err := st.View(func(s *store.State) error {
			if d := s.Devices[dev]; d != nil {
				status = d.Status
			}
			return nil
		})
		return status, err
	}}

	tc, err := tlsConfig(filepath.Join(pkiDir, "layer-ca.crt"), filepath.Join(pkiDir, "service", "client.crt"),
		filepath.Join(pkiDir, "service", "client.key"), strings.Split(layerAddr, ":")[0])
	if err != nil {
		return err
	}
	answer := func(c mqtt.Client, m mqtt.Message) {
		p := strings.Split(m.Topic(), "/") // dev/<id>/<kind>/req
		if len(p) != 4 {
			return
		}
		var out any
		var ok bool
		var qos byte = 1
		switch p[2] {
		case "cred":
			out, ok = cred.Handle(p[1], m.Payload())
		case "sign":
			out, ok = sign.Handle(p[1], m.Payload())
			qos = 0 // an answer after the handshake timeout is useless
		}
		if !ok {
			return
		}
		b, _ := json.Marshal(out)
		c.Publish("dev/"+p[1]+"/"+p[2]+"/res", qos, false, b)
	}
	client(layerAddr, "svc-layer", tc, func(c mqtt.Client) {
		c.SubscribeMultiple(map[string]byte{"dev/+/cred/req": 1, "dev/+/sign/req": 1}, answer)
		log.Printf("layer broker %s: answering cred and sign", layerAddr)
	})

	// registry publishers, one per deployment
	pubs := map[string]mqtt.Client{}
	var deps map[string]*store.Deployment
	st.View(func(s *store.State) error { deps = s.Deployments; return nil })
	for id, dep := range deps {
		dd := filepath.Join(pkiDir, "deployments", id)
		tc, err := tlsConfig(filepath.Join(dd, "ca.crt"), filepath.Join(dd, "layer.crt"), filepath.Join(dd, "layer.key"),
			strings.Split(dep.Broker, ":")[0])
		if err != nil {
			return err
		}
		pubs[id] = client(dep.Broker, "layer", tc, func(mqtt.Client) { log.Printf("deployment %s: registry broker %s connected", id, dep.Broker) })
	}

	lastDigest := map[string]time.Time{}
	for range time.Tick(time.Second) {
		st.Update(func(s *store.State) error {
			var left []store.Message
			for _, m := range s.Outbox {
				defer func(dep string) { delete(lastDigest, dep) }(m.Deployment) // a change: a fresh digest follows
				c := pubs[m.Deployment]
				if c == nil || !c.IsConnectionOpen() {
					left = append(left, m)
					continue
				}
				t := c.Publish(m.Topic, 1, true, []byte(m.Payload))
				if !t.WaitTimeout(5*time.Second) || t.Error() != nil {
					left = append(left, m)
				}
			}
			s.Outbox = left
			for id, c := range pubs {
				// the digest goes after every change and once a day, only with an empty queue for the deployment
				if time.Since(lastDigest[id]) < 24*time.Hour || !c.IsConnectionOpen() || waiting(s, id) {
					continue
				}
				if t := c.Publish("registry/digest", 1, true, []byte(s.Digest(id, time.Now()))); t.WaitTimeout(5*time.Second) && t.Error() == nil {
					lastDigest[id] = time.Now()
				}
			}
			return nil
		})
	}
	return nil
}

func waiting(s *store.State, dep string) bool {
	for _, m := range s.Outbox {
		if m.Deployment == dep {
			return true
		}
	}
	return false
}
