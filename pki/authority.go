// Copyright (C) 2021 - 2022 iDigitalFlame
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/iDigitalFlame/akcss/xerr"
)

// Authority is a struct that contains a listing of Certificates and can generate
// a full PKI stack.
//
// This struct can be Marshaled into JSON to save/load the PKI configuration.
type Authority struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate

	Subject   Subject        `json:"subject"`
	Directory string         `json:"dir"`
	Issued    []*Certificate `json:"certificates"`
	lock      sync.RWMutex

	Lifetime Lifetime `json:"lifetime"`
}

func random() *big.Int {
	var (
		n = new(big.Int)
		b [8]byte
	)
	rand.Read(b[:])
	n.SetBytes(b[:])
	return n
}
func (a *Authority) init() error {
	if a.cert != nil {
		return nil
	}
	var (
		c      = filepath.Join(a.Directory, "ca.crt")
		k      = filepath.Join(a.Directory, "ca.pem")
		b, err = os.ReadFile(c)
	)
	if err != nil {
		return err
	}
	d, _ := pem.Decode(b)
	if d == nil {
		return xerr.New(`"` + c + `" does not contain valid certificate data`)
	}
	if a.cert, err = x509.ParseCertificate(d.Bytes); err != nil {
		return xerr.Wrap(`certificate "`+c+`" could not be parsed`, err)
	}
	if b, err = os.ReadFile(k); err != nil {
		return err
	}
	if d, _ = pem.Decode(b); d == nil {
		return xerr.New(`"` + k + `" does not contain valid private key data`)
	}
	if a.key, err = x509.ParseECPrivateKey(d.Bytes); err != nil {
		return xerr.Wrap(`private key "`+k+`" could not be parsed`, err)
	}
	return nil
}

// File returns the full path to the Authority CA public certificate file.
func (a *Authority) File() string {
	return filepath.Join(a.Directory, "ca.crt")
}
func (a *Authority) newSerial() big.Int {
	a.lock.RLock()
	for n := random(); ; n = random() {
		if a.cert.SerialNumber.Cmp(n) == 0 {
			continue
		}
		for i := range a.Issued {
			if a.Issued[i].Serial.Cmp(n) == 0 {
				goto found
			}
		}
		a.lock.RUnlock()
		return *n
	found:
	}
}
func (a *Authority) crl() ([]Update, error) {
	if err := a.init(); err != nil {
		return nil, err
	}
	var (
		t   = time.Now()
		s   []Update
		r   []pkix.RevokedCertificate
		err error
	)
	if t.After(a.cert.NotAfter) {
		return nil, xerr.New(`CA certificate "` + a.cert.Subject.CommonName + `" has expired`)
	}
	a.lock.Lock()
	for i := range a.Issued {
		if err = a.Issued[i].init(); err != nil {
			if err == errRevoked {
				err, r = nil, append(r, pkix.RevokedCertificate{RevocationTime: *a.Issued[i].Revoked, SerialNumber: &a.Issued[i].Serial})
				continue
			}
			if !os.IsNotExist(err) {
				break
			}
		} else if !t.After(a.Issued[i].NotAfter) && a.Issued[i].Status == statusValid {
			continue
		}
		if len(a.Issued[i].Key) > 0 {
			os.Remove(a.Issued[i].Key)
		}
		if len(a.Issued[i].File) > 0 {
			os.Remove(a.Issued[i].File)
		}
		n := a.Issued[i].Revoked == nil || a.Issued[i].Revoked.IsZero()
		if n {
			a.Issued[i].Revoked = &t
		}
		r = append(r, pkix.RevokedCertificate{RevocationTime: *a.Issued[i].Revoked, SerialNumber: &a.Issued[i].Serial})
		if a.Issued[i].Status != statusRevoked {
			a.Issued[i].Status = statusExpired
		}
		if !n {
			continue
		}
		s = append(s, Update{Name: a.Issued[i].Name, Expired: a.Issued[i].Status == statusExpired})
		a.Issued[i].Key, a.Issued[i].File, a.Issued[i].Name = "", "", ""
	}
	if a.lock.Unlock(); err != nil {
		return nil, err
	}
	b, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Issuer:              a.cert.Issuer,
		ThisUpdate:          t,
		NextUpdate:          t.AddDate(0, 0, a.Lifetime.crl()),
		RevokedCertificates: r,
	}, a.cert, a.key)
	if err != nil {
		return nil, xerr.Wrap("could not generate CRL", err)
	}
	f, err := os.OpenFile(filepath.Join(a.Directory, "crl.pem"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(f, &pem.Block{Type: "X509 CRL", Bytes: b})
	f.Close()
	os.Chmod(filepath.Join(a.Directory, "crl.pem"), 0644)
	return s, err
}

// Write writes the data of the CA Certificate to the specified Writer.
//
// This function will return any errors that occurred during the encoding process.
func (a *Authority) Write(w io.Writer) error {
	if err := a.init(); err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
}

// Update will generate the CRL file and save it under the 'Directory' path.
//
// This function will also save the Authority certificate and key files, if not
// yet created. Any certificates that have been revoked or expired will be saved
// once this function is called.
func (a *Authority) Update() ([]Update, error) {
	r, err := a.crl()
	if err != nil {
		return nil, err
	}
	var (
		c = filepath.Join(a.Directory, "ca.crt")
		k = filepath.Join(a.Directory, "ca.pem")
	)
	if _, err := os.Stat(c); err != nil {
		if !os.IsNotExist(err) {
			return nil, xerr.Wrap(`could not open "`+c+`"`, err)
		}
		f, err := os.OpenFile(c, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return r, err
		}
		err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
		if f.Close(); err != nil {
			return r, xerr.Wrap(`could not encode certificate to "`+c+`"`, err)
		}
		os.Chmod(c, 0644)
	}
	if _, err := os.Stat(k); err != nil {
		if !os.IsNotExist(err) {
			return nil, xerr.Wrap(`could not open "`+k+`"`, err)
		}
		b, err := x509.MarshalECPrivateKey(a.key)
		if err != nil {
			return r, xerr.Wrap("could not encode private key data", err)
		}
		f, err := os.OpenFile(k, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
		if err != nil {
			return r, err
		}
		err = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		if f.Close(); err != nil {
			return r, xerr.Wrap(`could not encode private key to "`+k+`"`, err)
		}
		os.Chmod(k, 0400)
	}
	return r, nil
}

// Certificate will attempt to get the Certificate by the supplied subject name.
// If no Certificate is found that matches, nil is returned.
func (a *Authority) Certificate(n string) *Certificate {
	var (
		c *Certificate
		s = strings.ToLower(parseName(n))
	)
	a.lock.RLock()
	for i := range a.Issued {
		if a.Issued[i].Status != statusValid {
			continue
		}
		if strings.ToLower(a.Issued[i].Name) == s {
			c = a.Issued[i]
			break
		}
		if a.Issued[i].init() != nil {
			continue
		}
		if strings.ToLower(a.Issued[i].Subject.CommonName) == s {
			c = a.Issued[i]
			break
		}
	}
	a.lock.RUnlock()
	return c
}

// New creates a new Authority with the following options, Name, FileSystem directory,
// length of the CA certificate and the initial Authority Subject details.
func New(name, dir string, days uint64, s Subject) (*Authority, error) {
	if i, err := os.Stat(dir); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, err
		}
		os.Chmod(dir, 0755)
	} else if !i.IsDir() {
		return nil, xerr.New(`invalid directory path "` + dir + `"`)
	}
	var (
		err error
		a   = &Authority{
			Issued:    make([]*Certificate, 0),
			Subject:   s,
			Lifetime:  Lifetime{CRL: 60, Client: 365, Server: 720},
			Directory: dir,
		}
	)
	if len(name) == 0 {
		name = "CA"
	}
	a.cert, a.key, err = newCert(nil, nil, name, "", days, *random(), s, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature)
	if err != nil {
		return nil, xerr.Wrap("could not generate CA certificate", err)
	}
	if _, err := a.Update(); err != nil {
		return nil, err
	}
	return a, nil
}

// CreateClient attempts to create a new client certificate from this CA. The name
// and email are recommended, but optional.
//
// If the days parameter is less than or equal to zero, the default CA client timespan
// will be used.
func (a *Authority) CreateClient(name, email string, days int) (*Certificate, error) {
	if days <= 0 {
		days = a.Lifetime.client()
	}
	return a.createCert(name, email, uint64(days), x509.KeyUsageDigitalSignature, x509.ExtKeyUsageClientAuth)
}

// CreateServer attempts to create a new server certificate from this CA. The name
// and email are recommended, but optional.
//
// If the days parameter is less than or equal to zero, the default CA server timespan
// will be used.
func (a *Authority) CreateServer(name, email string, days int) (*Certificate, error) {
	if days <= 0 {
		days = a.Lifetime.server()
	}
	return a.createCert(name, email, uint64(days), x509.KeyUsageDigitalSignature, x509.ExtKeyUsageServerAuth)
}
func (a *Authority) createCert(name, email string, days uint64, use x509.KeyUsage, ext ...x509.ExtKeyUsage) (*Certificate, error) {
	if len(name) == 0 {
		return nil, errInvalid
	}
	if err := a.init(); err != nil {
		return nil, err
	}
	var (
		d      = filepath.Join(a.Directory, "certs")
		i, err = os.Stat(d)
	)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err = os.MkdirAll(d, 0700); err != nil {
			return nil, err
		}
		os.Chmod(d, 0700)
	} else if !i.IsDir() {
		return nil, xerr.New(`directory "` + d + `" is not valid`)
	}
	if a.Certificate(name) != nil {
		return nil, xerr.New(`certificate name "` + name + `" already exists`)
	}
	c, p, err := newCert(a.cert, a.key, name, email, days, a.newSerial(), a.Subject, use, ext...)
	if err != nil {
		return nil, xerr.Wrap(`could not create certificate`, err)
	}
	n := &Certificate{
		Key:         filepath.Join(d, c.SerialNumber.String()+".pem"),
		File:        filepath.Join(d, c.SerialNumber.String()+".crt"),
		Name:        parseName(name),
		Serial:      *c.SerialNumber,
		PrivateKey:  p,
		Certificate: c,
	}
	if err := n.writeFile(n.File); err != nil {
		return nil, xerr.Wrap(`could not create certificate "`+n.File+`"`, err)
	}
	if err := n.writeKey(n.Key); err != nil {
		return nil, xerr.Wrap(`could not create key "`+n.File+`"`, err)
	}
	a.lock.Lock()
	a.Issued = append(a.Issued, n)
	a.lock.Unlock()
	return n, nil
}
func newCert(ca *x509.Certificate, k *ecdsa.PrivateKey, name, email string, days uint64, i big.Int, s Subject, u x509.KeyUsage, e ...x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if len(name) == 0 {
		name = i.String()
	}
	var (
		err error
		p   *ecdsa.PrivateKey
		t   = time.Now()
		c   = &x509.Certificate{
			IsCA:                  ca == nil,
			Subject:               s.name(name),
			Version:               0,
			KeyUsage:              u,
			NotAfter:              t.AddDate(0, 0, int(days)),
			NotBefore:             t,
			ExtKeyUsage:           e,
			SerialNumber:          &i,
			EmailAddresses:        s.email(email),
			PublicKeyAlgorithm:    x509.ECDSA,
			SignatureAlgorithm:    x509.ECDSAWithSHA512,
			BasicConstraintsValid: true,
		}
	)
	if ca != nil && c.NotAfter.After(ca.NotAfter) {
		return nil, nil, xerr.New(
			"cannot create certificate that expires (" + c.NotAfter.Format(time.ANSIC) +
				") after the CA (" + ca.NotAfter.Format(time.ANSIC) + ")",
		)
	}
	c.DNSNames = []string{c.Subject.CommonName}
	if p, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader); err != nil {
		return nil, nil, err
	}
	if c.PublicKey = p.Public(); ca == nil {
		c.Raw, err = x509.CreateCertificate(rand.Reader, c, c, c.PublicKey, p)
	} else {
		c.Raw, err = x509.CreateCertificate(rand.Reader, c, ca, c.PublicKey, k)
	}
	return c, p, err
}
