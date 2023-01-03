// Copyright (C) 2021 - 2023 iDigitalFlame
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

package akcss

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/iDigitalFlame/akcss/userid"
)

func valid(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := range s {
		if s[i] < 45 || s[i] >= 127 {
			return false
		}
		switch s[i] {
		case '/', '@', '`', '[', ']', '\\', '^', ':', ';', '<', '=', '>', '?', '{', '}', '|', '~', '.':
			return false
		}
	}
	return true
}
func isUnix(s string) bool {
	if len(s) < 6 {
		return false
	}
	switch {
	case s[0] != 'u' && s[0] != 'U':
		fallthrough
	case s[1] != 'n' && s[1] != 'N':
		fallthrough
	case s[2] != 'i' && s[2] != 'I':
		fallthrough
	case s[3] != 'x' && s[3] != 'X':
		fallthrough
	case s[4] != ':':
		return false
	}
	return true
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
func confirm(s string, d bool) bool {
	os.Stdout.WriteString(s + " ")
	var (
		b      = make([]byte, 128)
		r, err = os.Stdin.Read(b)
	)
	if err != nil || r <= 1 {
		return d
	}
	switch strings.ToLower(string(b[:r-1])) {
	case "confirm", "true", "yes", "t", "y", "1":
		return true
	}
	return d
}
func (m *manager) perms(p string, d fs.DirEntry, _ error) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	n, err := userid.Nobody()
	if err != nil {
		return err
	}
	if !d.IsDir() {
		if strings.EqualFold(d.Name(), "crl.pem") {
			if err := os.Chown(p, 0, n); err != nil {
				return err
			}
			return os.Chmod(p, 0644)
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".crt":
			if err := os.Chown(p, 0, n); err != nil {
				return err
			}
			return os.Chmod(p, 0440)
		case ".pem":
			fallthrough
		case ".conf":
			if err := os.Chown(p, 0, 0); err != nil {
				return err
			}
			return os.Chmod(p, 0400)
		}
		return nil
	}
	switch {
	case strings.EqualFold(d.Name(), "certs"):
		fallthrough
	case strings.HasPrefix(m.Config.Dirs.CA, p):
		if err := os.Chown(p, 0, n); err != nil {
			return err
		}
		return os.Chmod(p, 0755)
	case strings.HasPrefix(m.Config.Dirs.Config, p):
		if err := os.Chown(p, 0, 0); err != nil {
			return err
		}
		return os.Chmod(p, 0700)
	}
	return nil
}
