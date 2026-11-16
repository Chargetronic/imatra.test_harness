// Package pki creates every trust root of the harness on first start and
// issues the certificates the test layer hands out. Nothing here is ever
// loaded from outside the installation (TK-1, TK-3, TK-5).
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ClassBench marks every device certificate this harness issues (TK-4).
const ClassBench = "bench"

// Authority is a CA certificate with its key.
type Authority struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n
}

// NewKey: a P-256 key.
func NewKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// NewRoot: a self-signed CA, 10 years.
func NewRoot(cn string) (*Authority, error) {
	k, err := NewKey()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Imatra test harness"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	c, _ := x509.ParseCertificate(der)
	return &Authority{Cert: c, Key: k, PEM: CertPEM(der)}, nil
}

// Kind of certificate issued.
type Kind int

const (
	Client Kind = iota
	Server
	Leaf // SECC: TLS server to the EV
)

// Issue a certificate for pub. ou may be empty; names are DNS names or IPs (server).
func (a *Authority) Issue(cn, ou string, pub *ecdsa.PublicKey, ttl time.Duration, kind Kind, names ...string) ([]byte, *x509.Certificate, error) {
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Imatra test harness"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if ou != "" {
		tpl.Subject.OrganizationalUnit = []string{ou}
	}
	switch kind {
	case Client:
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case Server, Leaf:
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, n := range names {
			if ip := net.ParseIP(n); ip != nil {
				tpl.IPAddresses = append(tpl.IPAddresses, ip)
			} else {
				tpl.DNSNames = append(tpl.DNSNames, n)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.Cert, pub, a.Key)
	if err != nil {
		return nil, nil, err
	}
	c, _ := x509.ParseCertificate(der)
	return CertPEM(der), c, nil
}

// CertPEM, KeyPEM: PEM encodings.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func KeyPEM(k *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// SPKI: SHA-256 of the DER public key, hex.
func SPKI(pub *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}

// ParseCSR: a PEM P-256 CSR with a valid signature.
func ParseCSR(b []byte) (*x509.CertificateRequest, *ecdsa.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, err
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("key must be ECDSA P-256")
	}
	return csr, pub, nil
}

// --- files

// Save writes a certificate and its key as NAME.crt and NAME.key in dir.
func Save(dir, name string, certPEM []byte, key *ecdsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"), certPEM, 0o644); err != nil {
		return err
	}
	if key != nil {
		return os.WriteFile(filepath.Join(dir, name+".key"), KeyPEM(key), 0o600)
	}
	return nil
}

// LoadAuthority reads NAME.crt and NAME.key from dir.
func LoadAuthority(dir, name string) (*Authority, error) {
	cb, err := os.ReadFile(filepath.Join(dir, name+".crt"))
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		return nil, err
	}
	cblk, _ := pem.Decode(cb)
	kblk, _ := pem.Decode(kb)
	if cblk == nil || kblk == nil {
		return nil, fmt.Errorf("%s: not PEM", name)
	}
	c, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an EC key", name)
	}
	return &Authority{Cert: c, Key: ek, PEM: cb}, nil
}

// Exists: NAME.crt is in dir.
func Exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name+".crt"))
	return err == nil
}
