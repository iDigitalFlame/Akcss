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

package vpn

import (
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/iDigitalFlame/akcss/userid"
	"github.com/iDigitalFlame/akcss/xerr"
)

// Protocol Type Constants
const (
	TCP = protocol(true)
	UDP = protocol(false)
)

type protocol bool
type action uint16

// Status is a struct that contains the data from an OpenVPN status entry.
type Status struct {
	Name   string    `json:"name"`
	Start  time.Time `json:"start"`
	Local  string    `json:"local"`
	Remote string    `json:"remote"`
	Cipher string    `json:"cipher"`
}
type option struct {
	Value  string `json:"value"`
	Push   bool   `json:"push,omitempty"`
	Client bool   `json:"client,omitempty"`
}
type overvalue struct {
	Value string
	Unset bool
}
type notification struct {
	Email  string `json:"email"`
	Events action `json:"events,omitempty"`
}
type override map[string]overvalue

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
func exp(s string, l int) string {
	if len(s) >= l {
		return s
	}
	b := make([]byte, l)
	copy(b, s)
	for i := len(s); i < l; i++ {
		b[i] = 32
	}
	return string(b)
}
func (p protocol) String() string {
	if p {
		return "tcp"
	}
	return "udp"
}
func lastMessage(s string) string {
	f, err := os.Open(s)
	if err != nil {
		return ""
	}
	f.Seek(350, 2)
	var b strings.Builder
	_, err = io.Copy(&b, f)
	v := b.String()
	b.Reset()
	if f.Close(); err != nil {
		return ""
	}
	return v
}
func loadOverride(f string) (override, error) {
	if len(f) == 0 {
		return nil, nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var (
		l = strings.Split(string(b), "\n")
		o = make(override)
	)
	for i := range l {
		if len(l[i]) == 0 {
			continue
		}
		v := strings.TrimSpace(l[i])
		if len(v) <= 1 || v[0] == '#' || v[0] == ';' {
			continue
		}
		if x := strings.IndexByte(v, ' '); x > 0 {
			if v[0] == '!' {
				o[strings.ToLower(strings.TrimSpace(v[:x]))] = overvalue{Unset: true}
				continue
			}
			o[strings.ToLower(strings.TrimSpace(v[:x]))] = overvalue{Value: strings.TrimSpace(v[x+1:])}
			continue
		}
		if v[0] == '!' {
			o[strings.ToLower(v[1:])] = overvalue{Unset: true}
			continue
		}
		o[strings.ToLower(v[1:])] = overvalue{Value: v[1:]}
	}
	return o, nil
}
func (p protocol) MarshalJSON() ([]byte, error) {
	return []byte(`"` + p.String() + `"`), nil
}
func (p *protocol) UnmarshalJSON(b []byte) error {
	if len(b) < 3 || b[0] != '"' {
		return xerr.New(`invalid value "` + string(b) + `" for protocol string`)
	}
	switch b[1] {
	case 'u', 'U':
		*p = UDP
	default:
		*p = TCP
	}
	return nil
}
func perms(p string, d fs.DirEntry, _ error) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	n, err := userid.Nobody()
	if err != nil {
		return err
	}
	if d.IsDir() {
		if err := os.Chmod(p, 0750); err != nil {
			return err
		}
		return os.Chown(p, 0, n)
	}
	switch d.Name() {
	case "ip.log":
		fallthrough
	case "status.log":
		if err := os.Chmod(p, 0660); err != nil {
			return err
		}
		return os.Chown(p, 0, n)
	case "server.log":
		if err := os.Chmod(p, 0600); err != nil {
			return err
		}
		return os.Chown(p, 0, 0)
	default:
	}
	if err := os.Chmod(p, 0640); err != nil {
		return err
	}
	return os.Chown(p, 0, n)
}
func (o override) Get(s *Server, name, value string) string {
	if len(o) == 0 {
		if len(value) == 0 {
			return name
		}
		return name + " " + value
	}
	v, ok := o[name]
	if !ok {
		if len(value) == 0 {
			return name
		}
		return name + " " + value
	}
	if v.Unset {
		s.log.Debug("[server/override] %s: Value name %q unset by override!", s.ID, name)
		return ""
	}
	s.log.Debug("[server/override] %s: Value name %q overridden to %q!", s.ID, name, v.Value)
	if len(v.Value) == 0 {
		return name
	}
	return name + " " + v.Value
}
