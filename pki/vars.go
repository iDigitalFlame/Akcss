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
	"crypto/x509/pkix"

	"github.com/iDigitalFlame/akcss/xerr"
)

const (
	statusValid   status = 0
	statusRevoked status = iota
	statusExpired
	statusUnknown
)

type status uint8

// Update is a struct that can be returned from an Update function to indicate the certificates that may
// have expired of were revoked during the previous CRL period.
type Update struct {
	Name    string
	Expired bool
}

// Subject is a struct that can be used to generate a 'pkix.Name' struct from a loaded JSON structure.
type Subject struct {
	ZIP          string `json:"zip,omitempty"`
	City         string `json:"city,omitempty"`
	State        string `json:"state,omitempty"`
	Email        string `json:"email,omitempty"`
	Street       string `json:"street,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Country      string `json:"country"`
	Department   string `json:"department,omitempty"`
	Organization string `json:"organization"`
}

// Lifetime is a struct that stores the days that each type of certificate will be valid for.
// This can be overridden during certificate generation.
type Lifetime struct {
	CRL    uint16 `json:"crl_days"`
	Client uint16 `json:"client_days"`
	Server uint16 `json:"server_days"`
}

func (l Lifetime) crl() int {
	if l.CRL == 0 {
		return 60
	}
	return int(l.CRL)
}
func (l Lifetime) client() int {
	if l.Client == 0 {
		return 365
	}
	return int(l.Client)
}
func (l Lifetime) server() int {
	if l.Server == 0 {
		return 720
	}
	return int(l.Server)
}
func parseName(s string) string {
	if len(s) == 0 {
		return s
	}
	r := make([]byte, 0, len(s))
	for i := range s {
		if s[i] < 45 || s[i] >= 127 {
			continue
		}
		switch s[i] {
		case '/', '@', '`', '[', ']', '\\', '^', ':', ';', '<', '=', '>', '?', '{', '}', '|', '~':
			continue
		}
		r = append(r, s[i])
	}
	return string(r)
}
func (s status) String() string {
	switch s {
	case statusValid:
		return "V"
	case statusExpired:
		return "I"
	case statusRevoked:
		return "R"
	}
	return "U"
}
func (s Subject) name(n string) pkix.Name {
	return pkix.Name{
		Country:            []string{s.Country},
		Locality:           []string{s.City},
		Province:           []string{s.State},
		PostalCode:         []string{s.ZIP},
		CommonName:         parseName(n),
		Organization:       []string{s.Organization},
		StreetAddress:      []string{s.Street},
		OrganizationalUnit: []string{s.Department},
	}
}
func (s Subject) email(n string) []string {
	if len(s.Email) == 0 {
		return nil
	}
	e := []string{s.Email}
	if len(n) == 0 {
		return e
	}
	return append(e, n)
}
func (s status) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}
func (s *status) UnmarshalJSON(b []byte) error {
	if len(b) < 3 || b[0] != '"' {
		return xerr.New(`invalid status value "` + string(b) + `"`)
	}
	switch b[1] {
	case 'v', 'V':
		*s = statusValid
	case 'i', 'I':
		*s = statusExpired
	case 'r', 'R':
		*s = statusRevoked
	default:
		*s = statusUnknown
	}
	return nil
}
