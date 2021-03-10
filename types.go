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

package akcss

import (
	"time"

	"github.com/iDigitalFlame/akcss/vpn"
)

type typeServer struct {
	*vpn.Server
}
type typeOption struct {
	ID     string `json:"id"`
	Value  string `json:"value"`
	Client string `json:"client"`
	Push   bool   `json:"push,omitempty"`
	Config bool   `json:"config,omitempty"`
}
type typeStatus struct {
	Status []vpn.Status `json:"status,omitempty"`
	PID    uint64       `json:"pid"`
}
type typeNotify struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Action string `json:"action,omitempty"`
}
type typeConnect struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Local    string        `json:"local,omitempty"`
	Remote   string        `json:"remote,omitempty"`
	Duration time.Duration `json:"time,omitempty"`
}
type typeClientNew struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	Days  uint16 `json:"days,omitempty"`
}
type typeClientList struct {
	Clients []string `json:"clients"`
}
type typeNotifyList struct {
	Notifiers []typeNotify
}
type typeOptionList struct {
	Options []typeOption
}
type typeServerList struct {
	Servers []typeServerListObj `json:"servers,omitempty"`
}
type typeServerDelete struct {
	ID   string `json:"id"`
	Soft bool   `json:"soft,omitempty"`
}
type typeClientDelete struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type typeServerListObj struct {
	ID       string `json:"id"`
	Protocol string `json:"proto,omitempty"`
	Hostname string `json:"name"`
	PID      uint64 `json:"pid,omitempty"`
	Port     uint16 `json:"port"`
	Auto     bool   `json:"auto,omitempty"`
	Running  bool   `json:"running,omitempty"`
}

func (d details) id() string {
	return d.ID
}
func (t typeOption) id() string {
	return t.ID
}
func (t typeNotify) id() string {
	return t.ID
}
func (t typeServer) id() string {
	return t.ID
}
func (t typeConnect) id() string {
	return t.ID
}
func (m typeServerList) Len() int {
	return len(m.Servers)
}
func (t typeClientNew) id() string {
	return t.ID
}
func (t typeServerDelete) id() string {
	return t.ID
}
func (t typeClientDelete) id() string {
	return t.ID
}
func (m *typeServerList) Swap(i, j int) {
	m.Servers[i], m.Servers[j] = m.Servers[j], m.Servers[i]
}
func (m typeServerList) Less(i, j int) bool {
	return m.Servers[i].ID < m.Servers[j].ID
}
