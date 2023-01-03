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

package xerr

type err struct {
	e error
	s string
}
type strErr string

// New creates a new string backed error struct and returns it. This error struct
// does not support Unwrapping.
//
// The resulting structs created will be comparable.
func New(s string) error {
	return strErr(s)
}
func (e err) Error() string {
	return e.s
}
func (e err) String() string {
	return e.s
}
func (e strErr) Error() string {
	return string(e)
}
func (e strErr) String() string {
	return string(e)
}

// Wrap creates a new error that wraps the specified error. If not nil, this
// function will append ": " + 'Error()' to the resulting string message.
func Wrap(s string, e error) error {
	if e != nil {
		return &err{s: s + ": " + e.Error(), e: e}
	}
	return &err{s: s}
}
