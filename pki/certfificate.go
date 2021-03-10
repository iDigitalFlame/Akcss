// Copyright (C) 2021 iDigitalFlame
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
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/iDigitalFlame/akcss/xerr"
)

var (
	errInvalid    = xerr.New("certificate name is invalid")
	errRevoked    = xerr.New("certificate was revoked")
	errPrivateKey = xerr.New("no private key found")
)

// Certificate is a struct representation of an x509 Certificate. This struct contains some functions for convince
// and easy management. The certificate data is not loaded from the specified file path until it is needed.
type Certificate struct {
	PrivateKey        *ecdsa.PrivateKey `json:"-"`
	*x509.Certificate `json:"-"`

	Revoked *time.Time `json:"revoked,omitempty"`
	Name    string     `json:"name,omitempty"`
	Key     string     `json:"key_file,omitempty"`
	File    string     `json:"cert_file,omitempty"`
	Serial  big.Int    `json:"serial"`
	Status  status     `json:"status,omitempty"`
}

// Revoke will revoke the Certificate if not already revoked. This function does not return any values. The CRL
// must be regenerated using the 'Authority.Update()' function in order to take affect.
func (c *Certificate) Revoke() {
	c.PrivateKey = nil
	c.Status = statusRevoked
}
func (c *Certificate) init() error {
	if c.Certificate != nil {
		return nil
	}
	if len(c.File) == 0 {
		return errRevoked
	}
	b, err := ioutil.ReadFile(c.File)
	if err != nil {
		return err
	}
	d, _ := pem.Decode(b)
	if d == nil {
		return xerr.New(`"` + c.File + `" does not contain valid certificate data`)
	}
	if c.Certificate, err = x509.ParseCertificate(d.Bytes); err != nil {
		return xerr.Wrap(`certificate "`+c.File+`" could not be parsed`, err)
	}
	if len(c.Key) == 0 {
		return nil
	}
	if _, err := os.Stat(c.Key); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if b, err = ioutil.ReadFile(c.Key); err != nil {
		return err
	}
	if d, _ = pem.Decode(b); d == nil {
		return xerr.New(`"` + c.Key + `" does not contain valid private key data`)
	}
	if c.PrivateKey, err = x509.ParseECPrivateKey(d.Bytes); err != nil {
		return xerr.Wrap(`private key "`+c.Key+`" could not be parsed`, err)
	}
	return nil
}

// Valid returns true if the certificate is valid and is not expired nor revoked.
func (c *Certificate) Valid() bool {
	return c.Status == statusValid
}

// String returns a string representation of this Certificate.
func (c *Certificate) String() string {
	return c.Name + " (" + strconv.FormatUint(c.SerialNumber.Uint64(), 16) + ")"
}

// Write writes the data of this Certificate to the specified Writer. This function will return any errors that
// occurred during the encoding process.
func (c *Certificate) Write(w io.Writer) error {
	if err := c.init(); err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
func (c *Certificate) writeKey(s string) error {
	f, err := os.OpenFile(s, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return err
	}
	err = c.WriteKey(f)
	err2 := f.Close()
	if err != nil {
		return err
	}
	os.Chmod(s, 0400)
	return err2
}
func (c *Certificate) writeFile(s string) error {
	f, err := os.OpenFile(s, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	err = c.Write(f)
	err2 := f.Close()
	if err != nil {
		return err
	}
	os.Chmod(s, 0640)
	return err2
}

// WriteKey will attempt to write the PrivateKey for this Certificate to the specified Writer. This function
// returns 'ErrPrivateKey' error if no PrivateKey is loaded. Any other errors will be returned if the encoding
// process fails.
func (c *Certificate) WriteKey(w io.Writer) error {
	if err := c.init(); err != nil {
		return err
	}
	if c.PrivateKey == nil {
		return errPrivateKey
	}
	b, err := x509.MarshalECPrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	return pem.Encode(w, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
}

// ValidFor returns true if the certificate is valid and is not expired nor revoked and ensures it will be valid
// for the suplied time duration.
func (c *Certificate) ValidFor(d time.Duration) bool {
	if !c.Valid() || c.init() != nil {
		return false
	}
	if c.Certificate == nil {
		return false
	}
	if t := time.Now().Add(d); t.After(c.Certificate.NotAfter) {
		return false
	}
	return true
}
