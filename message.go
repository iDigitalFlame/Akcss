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
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/iDigitalFlame/akcss/xerr"
)

const (
	timeout          = time.Second * 5
	responseOk uint8 = iota
	responseStatus
	responseServerList
	responseClientNew
	responseClientList
	responseNotifyList
	responseOptionList
	responseOptionClientList
	responseShow
	actionCRL
	actionStop
	actionStart
	actionRenew
	actionReload
	actionStatus
	actionUpdate
	actionRestart
	actionShow
	actionNotifyNew
	actionNotifyList
	actionNotifyDelete
	actionConnect
	actionDisconnect
	actionOptionNew
	actionOptionList
	actionOptionDelete
	actionOptionClientNew
	actionOptionClientList
	actionOptionClientDelete
	actionServerNew
	actionClientNew
	actionServerDelete
	actionClientDelete
	actionServerList
	actionClientList
	responseError
)

var (
	bufs = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 512)
			return &b
		},
	}
	local = new(net.Dialer)
)

type message struct {
	e      interface{}
	Data   []byte
	Action uint8
}
type payload interface {
	id() string
}

func (m *message) Parse() error {
	if len(m.Data) == 0 || m.e != nil {
		return nil
	}
	switch m.Action {
	case responseShow:
		m.e = new(typeServer)
	case responseStatus:
		m.e = new(typeStatus)
	case actionClientNew:
		m.e = new(typeClientNew)
	case actionClientDelete:
		m.e = new(typeClientDelete)
	case responseNotifyList:
		m.e = new(typeNotifyList)
	case responseClientList:
		m.e = new(typeClientList)
	case responseServerList:
		m.e = new(typeServerList)
	case actionServerDelete:
		m.e = new(typeServerDelete)
	case actionUpdate, actionServerNew:
		m.e = new(details)
	case actionConnect, actionDisconnect:
		m.e = new(typeConnect)
	case actionNotifyNew, actionNotifyDelete:
		m.e = new(typeNotify)
	case responseOptionList, responseOptionClientList:
		m.e = new(typeOptionList)
	case actionOptionNew, actionOptionDelete, actionOptionClientNew, actionOptionClientDelete:
		m.e = new(typeOption)
	default:
		return nil
	}
	return json.Unmarshal(m.Data, &m.e)
}
func (m message) String() string {
	var s string
	switch m.Action {
	case responseOk:
		return "Ok"
	case responseStatus:
		return "Status"
	case responseServerList:
		return "ServerList"
	case responseClientNew:
		return "ClientNew"
	case responseClientList:
		return "ClientList"
	case responseNotifyList:
		return "NotifyList"
	case responseOptionList:
		return "OptionList"
	case responseOptionClientList:
		return "OptionClientList"
	case responseShow:
		return "Show"
	case actionConnect:
		s = "Connect"
	case actionDisconnect:
		s = "Disconnect"
	case actionCRL:
		s = "CRL"
	case actionStop:
		s = "Stop"
	case actionStart:
		s = "Start"
	case actionRenew:
		s = "Renew"
	case actionReload:
		return "Reload"
	case actionStatus:
		s = "Status"
	case actionUpdate:
		return "Update"
	case actionRestart:
		s = "Restart"
	case actionShow:
		s = "Show"
	case actionNotifyNew:
		return "NotifyNew"
	case actionNotifyList:
		s = "NotifyList"
	case actionNotifyDelete:
		s = "NotifyDelete"
	case actionOptionNew:
		return "OptionNew"
	case actionOptionList:
		s = "OptionList"
	case actionOptionDelete:
		s = "OptionDelete"
	case actionOptionClientNew:
		return "OptionClientNew"
	case actionOptionClientList:
		s = "OptionClientList"
	case actionOptionClientDelete:
		s = "OptionClientDelete"
	case actionServerNew:
		return "ServerNew"
	case actionClientNew:
		return "ClientNew"
	case actionServerDelete:
		s = "ServerDelete"
	case actionClientDelete:
		s = "ClientDelete"
	case actionServerList:
		s = "ServerList"
	case actionClientList:
		s = "ClientList"
	case responseError:
		s = "Error"
	default:
		return "Unknown"
	}
	if len(m.Data) == 0 {
		return s
	}
	return s + "(" + string(m.Data) + ")"
}
func (m *message) ID() (string, error) {
	if len(m.Data) == 0 {
		return "", errInvalidID
	}
	if err := m.Parse(); err != nil {
		return "", err
	}
	if m.e == nil {
		return string(m.Data), nil
	}
	if v, ok := m.e.(payload); ok {
		return v.id(), nil
	}
	return "", errUnexpected
}
func (m message) Write(w io.Writer) error {
	if m.e != nil {
		return rawJSON(m.Action, m.e, w)
	}
	return raw(m.Action, m.Data, w)
}
func (m *message) Read(r io.Reader) error {
	var (
		b      = bufs.Get().(*[]byte)
		n, err = r.Read(*b)
	)
	if err != nil {
		bufs.Put(b)
		return err
	}
	if n == 0 {
		bufs.Put(b)
		return io.EOF
	}
	l := int(uint16((*b)[2]) | uint16((*b)[1])<<8)
	m.Action, m.Data = (*b)[0], make([]byte, n-3, l)
	if copy(m.Data, (*b)[3:n]); m.Action > responseError {
		return xerr.New(`invalid action value "` + strconv.Itoa(int(m.Action)) + `"`)
	}
	for l -= len(m.Data); l > 0; {
		if n, err = r.Read(*b); err == io.EOF && n == 0 {
			err = nil
			break
		}
		if err != nil {
			break
		}
		m.Data = append(m.Data, (*b)[:n]...)
		l -= n
	}
	bufs.Put(b)
	return err
}
func raw(a uint8, d []byte, w io.Writer) error {
	n := uint64(len(d))
	if n > maxUint16 {
		return xerr.New("message size is too large")
	}
	var (
		b   = bufs.Get().(*[]byte)
		err error
	)
	(*b)[0], (*b)[1], (*b)[2] = a, byte(n>>8), byte(n)
	if _, err = w.Write((*b)[0:3]); err == nil && len(d) > 0 {
		_, err = w.Write(d)
	}
	bufs.Put(b)
	return err
}
func rawJSON(a uint8, v interface{}, w io.Writer) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return raw(a, b, w)
}
func write(x context.Context, s string, n message) (*message, error) {
	var (
		c   net.Conn
		err error
	)
	if isUnix(s) {
		c, err = local.DialContext(x, "unix", s[5:])
	} else {
		c, err = local.DialContext(x, "tcp", s)
	}
	if err != nil {
		return nil, err
	}
	if err = n.Write(c); err != nil {
		c.Close()
		return nil, err
	}
	var r message
	if err = r.Read(c); err != nil {
		c.Close()
		return nil, err
	}
	return &r, c.Close()
}
