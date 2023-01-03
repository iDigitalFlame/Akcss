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
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/iDigitalFlame/akcss/pki"
	"github.com/iDigitalFlame/akcss/vpn"
	"github.com/iDigitalFlame/akcss/xerr"
)

func (s *server) edit(d *details) error {
	if d.DH.Size.S {
		s.DH.Size = d.DH.Size.V
	}
	if d.DH.Empty {
		s.DH.File, s.DH.Data = "", nil
	}
	if d.DH.File.S {
		s.DH.File = d.DH.File.V
	}
	if len(d.DH.Data) > 0 {
		s.DH.Data = d.DH.Data
	}
	if d.Config.Auto.S {
		s.Config.Auto = d.Config.Auto.V
	}
	if d.Config.Limits.Max.S {
		s.Config.Limits.Max = d.Config.Limits.Max.V
	}
	if d.Config.Limits.KeepAlive.Timeout.S {
		s.Config.Limits.KeepAlive.Timeout = d.Config.Limits.KeepAlive.Timeout.V
	}
	if d.Config.Limits.KeepAlive.Interval.S {
		s.Config.Limits.KeepAlive.Interval = d.Config.Limits.KeepAlive.Interval.V
	}
	if d.Config.Override.Client.S {
		s.Config.Override.Client = d.Config.Override.Client.V
	}
	if d.Config.Override.Server.S {
		s.Config.Override.Server = d.Config.Override.Server.V
	}
	if d.Network.Range.End.S {
		s.Network.Range.End = d.Network.Range.End.V
	}
	if d.Network.Range.Mask.S {
		s.Network.Range.Mask = d.Network.Range.Mask.V
	}
	if d.Network.Range.Base.S {
		s.Network.Range.Base = d.Network.Range.Base.V
	}
	if d.Network.Range.Start.S {
		s.Network.Range.Start = d.Network.Range.Start.V
	}
	if d.Network.Crosstalk.S {
		s.Network.Crosstalk = d.Network.Crosstalk.V
	}
	if d.Service.Auth.Empty {
		s.Service.Auth.File, s.Service.Auth.Data = "", nil
	}
	if d.Service.Auth.File.S {
		s.Service.Auth.File = d.Service.Auth.File.V
	}
	if len(d.Service.Auth.Data) > 0 {
		s.Service.Auth.Data = d.Service.Auth.Data
	}
	if d.Service.Port.S {
		s.Service.Port = d.Service.Port.V
	}
	if d.Service.Protocol.S {
		switch strings.ToLower(d.Service.Protocol.V) {
		case "udp", "u":
			s.Service.Protocol = vpn.UDP
		default:
			s.Service.Protocol = vpn.TCP
		}
	}
	if d.Subject.ZIP.S {
		s.CA.Subject.ZIP = d.Subject.ZIP.V
	}
	if d.Subject.City.S {
		s.CA.Subject.City = d.Subject.City.V
	}
	if d.Subject.State.S {
		s.CA.Subject.State = d.Subject.State.V
	}
	if d.Subject.Email.S {
		s.CA.Subject.Email = d.Subject.Email.V
	}
	if d.Subject.Street.S {
		s.CA.Subject.Street = d.Subject.Street.V
	}
	if d.Subject.Domain.S {
		s.CA.Subject.Domain = d.Subject.Domain.V
	}
	if d.Subject.Country.S {
		s.CA.Subject.Country = d.Subject.Country.V
	}
	if d.Subject.Department.S {
		s.CA.Subject.Department = d.Subject.Department.V
	}
	if d.Subject.Organization.S {
		s.CA.Subject.Organization = d.Subject.Organization.V
	}
	if d.Subject.Days.Server.S {
		s.CA.Lifetime.Server = d.Subject.Days.Server.V
	}
	if d.Subject.Days.Client.S {
		s.CA.Lifetime.Client = d.Subject.Days.Client.V
	}
	if d.Service.Hostname.S {
		if err := s.ChangeName(d.Service.Hostname.V); err != nil {
			return err
		}
	}
	return s.Save()
}
func (m *manager) new(_ context.Context, d *details) (*server, error) {
	var (
		p    uint16
		n, h string
	)
	if p = 4096; d.DH.Size.S {
		p = d.DH.Size.V
	}
	switch p {
	case 0, 2048, 4096:
	default:
		return nil, xerr.New(`dhparam prime size value must be 0, 2048 or 4096`)
	}
	if n = "CA"; d.Subject.CA.S && len(d.Subject.CA.V) > 0 {
		n = d.Subject.CA.V
	}
	if h = d.ID + "-server"; d.Service.Hostname.S && len(d.Service.Hostname.V) > 0 {
		h = d.Service.Hostname.V
	}
	var (
		k = filepath.Join(m.Config.Dirs.CA, d.ID)
		c = filepath.Join(m.Config.Dirs.Config, d.ID+".conf")
	)
	if _, err := os.Stat(k); err == nil {
		return nil, xerr.New(`server CA directory "` + k + `" already exists`)
	}
	if _, err := os.Stat(c); err == nil {
		return nil, xerr.New(`server config "` + c + `" already exists`)
	}
	var (
		o = pki.Subject{Country: strings.ToUpper(d.Subject.Country.V), Organization: d.Subject.Organization.V}
		i = 3650
	)
	if d.Subject.ZIP.S {
		o.ZIP = d.Subject.ZIP.V
	}
	if d.Subject.City.S {
		o.City = d.Subject.City.V
	}
	if d.Subject.State.S {
		o.State = d.Subject.State.V
	}
	if d.Subject.Email.S {
		o.Email = d.Subject.Email.V
	}
	if d.Subject.Street.S {
		o.Street = d.Subject.Street.V
	}
	if d.Subject.Domain.S {
		o.Domain = d.Subject.Domain.V
	}
	if d.Subject.Department.S {
		o.Department = d.Subject.Department.V
	}
	if d.Subject.Days.CA.S && d.Subject.Days.CA.V > 0 {
		i = int(d.Subject.Days.CA.V)
	}
	if d.Subject.Days.Client.S && d.Subject.Days.Client.V > uint16(i) {
		return nil, xerr.New(
			`client certificate lifetime "` + strconv.FormatUint(uint64(d.Subject.Days.Client.V), 10) +
				`" cannot be greater than the CA lifetime "` + strconv.FormatUint(uint64(i), 10) + `"`,
		)
	}
	if d.Subject.Days.Server.S && d.Subject.Days.Server.V > uint16(i) {
		return nil, xerr.New(
			`server certificate lifetime "` + strconv.FormatUint(uint64(d.Subject.Days.Server.V), 10) +
				`" cannot be greater than the CA lifetime "` + strconv.FormatUint(uint64(i), 10) + `"`,
		)
	}
	m.log.Debug(`[daemon/new] Generating PKI for "%s" at "%s"..`, d.ID, k)
	a, err := pki.New(n, k, uint64(i), o)
	if err != nil {
		return nil, err
	}
	s := &server{file: c, Server: (&vpn.Server{ID: d.ID, CA: a}).Init(m)}
	s.DH.Size, s.Service.Protocol, s.Service.Hostname = p, vpn.TCP, h
	m.log.Trace(`[daemon/new] Saving server "%s" config at "%s"..`, d.ID, c)
	if err = s.Save(); err != nil {
		os.RemoveAll(k)
		m.lock.Unlock()
		return nil, xerr.Wrap(`unable to save server configuration file "`+c+`"`, err)
	}
	m.servers[d.ID] = s
	m.log.Info(`[daemon/new] New server "%s" added!`, d.ID)
	return s, nil
}
func (m *manager) process(x context.Context, n message) (*message, error) {
	switch n.Action {
	case actionReload:
		m.log.Info("[daemon/process/reload] Triggering a manager reload..")
		m.log.Trace("[daemon/process/reload] Attempting to acquire manager lock..")
		m.lock.Lock()
		m.log.Trace("[daemon/process/reload] Manager lock acquired.")
		err := m.reload()
		if m.lock.Unlock(); err != nil {
			m.log.Error("[daemon/process/reload] Reload return an error: %s!", err.Error())
			return nil, err
		}
		m.log.Debug("[daemon/process/reload] Reload complete.")
		return nil, nil
	case actionServerList:
		m.log.Debug("[daemon/process/list] Generating a list of servers..")
		m.log.Trace("[daemon/process/list] Attempting to acquire manager read lock..")
		m.lock.RLock()
		l := &typeServerList{Servers: make([]typeServerListObj, 0, len(m.servers))}
		m.log.Trace("[daemon/process/list] Manager read lock acquired.")
		for _, v := range m.servers {
			l.Servers = append(l.Servers, typeServerListObj{
				ID:       v.ID,
				PID:      v.Pid(),
				Auto:     v.Config.Auto,
				Port:     v.Service.Port,
				Running:  v.Running(),
				Hostname: v.Service.Hostname,
				Protocol: v.Service.Protocol.String(),
			})
		}
		m.lock.RUnlock()
		sort.Sort(l)
		o, err := json.Marshal(l)
		if err != nil {
			m.log.Error("[daemon/process/list] Error marshaling server list: %s!", err.Error())
			return nil, err
		}
		return &message{Action: responseServerList, Data: o}, nil
	case responseError, responseOk:
		m.log.Warning("[daemon/process] Received an invalid message, ignoring!")
		return nil, nil
	}
	i, err := n.ID()
	if err != nil {
		if n.Action == actionCRL {
			m.log.Info("[daemon/process/crl] Triggering a full CRL generation.")
			m.log.Trace("[daemon/process/crl] Attempting to acquire manager read lock..")
			m.lock.RLock()
			m.log.Trace("[daemon/process/crl] Manager read lock acquired.")
			for k, s := range m.servers {
				m.log.Trace("[daemon/process/crl] %s: Attempting to acquire server lock..", s.ID)
				s.lock.Lock()
				m.log.Trace("[daemon/process/crl] %s: Server lock acquired.", s.ID)
				err = s.CRL()
				if s.lock.Unlock(); err != nil {
					m.log.Error("[daemon/process/crl] %s: Server failed CRL generation: %s!", k, err.Error())
					break
				}
				m.log.Debug("[daemon/process/crl] %s: Regenerated CRL.", k)
			}
			m.lock.RUnlock()
			return nil, err
		}
		m.log.Warning("[daemon/process] Received an invalid message: %s!", err.Error())
		return nil, err
	}
	if !valid(i) {
		return nil, xerr.New(`server ID "` + i + `" is invalid`)
	}
	m.log.Trace("[daemon/process] Attempting to acquire manager read lock..")
	m.lock.RLock()
	m.log.Trace("[daemon/process] Manager read acquired.")
	s, ok := m.servers[i]
	if m.lock.RUnlock(); n.Action == actionServerNew {
		if ok {
			m.log.Error(`[daemon/process/new] Received an existing server ID "%s" for new server request!`, i)
			return nil, xerr.New(`server with ID "` + i + `" already exists`)
		}
		v, ok2 := n.e.(*details)
		if !ok2 {
			m.log.Error("[daemon/process/new] Received an invalid message payload type %T!", n.e)
			return nil, errInvalidPayload
		}
		m.log.Trace("[daemon/process/new] Attempting to acquire manager lock..")
		m.lock.Lock()
		m.log.Trace("[daemon/process/new] Manager lock acquired.")
		if err = v.verify(true); err != nil {
			m.log.Error("[daemon/process/new] Could not validate new server details: %s!", err.Error())
			m.lock.Unlock()
			return nil, err
		}
		s, err = m.new(x, v)
		if err != nil {
			m.log.Error(`[daemon/process/new] Attempting to create a new server "%s" failed: %s!`, i, err.Error())
		}
		if err == nil && s != nil {
			m.log.Trace("[daemon/process/new] %s: Attempting to acquire server lock..", s.ID)
			s.lock.Lock()
			m.log.Trace("[daemon/process/new] %s: Server lock acquired.", s.ID)
			m.log.Debug("[daemon/process/new] %s: Editing new server, options [%+v]", s.ID, v)
			if err = s.edit(v); err != nil {
				m.log.Error(`[daemon/process/new] Attempting to edit server "%s" failed: %s!`, i, err.Error())
			}
			if s.lock.Unlock(); err == nil && v.Restart {
				err = s.Start()
			}
		}
		m.lock.Unlock()
		return nil, err
	}
	if !ok {
		m.log.Debug("[daemon/process] Received a message with an invalid server ID, ignoring!")
		return nil, xerr.Wrap(i, errInvalidID)
	}
	m.log.Debug(`[daemon/process] Message is for server ID "%s"..`, i)
	m.log.Trace("[daemon/process] %s: Checking for server lock..", s.ID)
	if s.lock.Locked() {
		return nil, xerr.New(`server "` + i + `" is currently locked for an operation`)
	}
	s.lock.Lock()
	m.log.Trace("[daemon/process] %s: Server lock acquired.", s.ID)
	r, w, err := s.process(x, m, n)
	if w {
		if err != nil {
			m.log.Warning("[daemon/process] %s: Received an error during previous operation (%s), attempting to save anyway!", s.ID, err.Error())
		}
		if err2 := s.Save(); err2 != nil {
			// We need to preserve the OG error.
			if err == nil {
				err = err2
			}
			m.log.Error("[daemon/process] %s: Saving server state failed: %s!", s.ID, err.Error())
		}
	}
	s.lock.Unlock()
	return r, err
}
func (s *server) process(_ context.Context, m *manager, n message) (*message, bool, error) {
	switch n.Action {
	case actionCRL:
		m.log.Debug("[daemon/process/crl] %s: Triggering a CRL generation..", s.ID)
		if err := s.CRL(); err != nil {
			m.log.Error("[daemon/process/crl] %s: CRL generation failed: %s!", s.ID, err.Error())
			return nil, true, err
		}
		return nil, true, nil
	case actionStop:
		m.log.Debug("[daemon/process/stop] %s: Stopping server..", s.ID)
		if err := s.Stop(); err != nil {
			m.log.Error("[daemon/process/stop] %s: Stopping server failed: %s!", s.ID, err.Error())
			return nil, true, err
		}
		return nil, true, nil
	case actionShow:
		o, err := json.Marshal(typeServer{s.Server})
		if err != nil {
			m.log.Error("[daemon/process/notify] %s: Marshaling server response failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		return &message{Action: responseShow, Data: o}, false, nil
	case actionStart:
		m.log.Debug("[daemon/process/start] %s: Starting server..", s.ID)
		if err := s.Start(); err != nil {
			m.log.Error("[daemon/process/start] %s: Starting server failed: %s!", s.ID, err.Error())
			return nil, true, err
		}
		return &message{Action: responseStatus, e: typeStatus{PID: s.Pid()}}, true, nil
	case actionRenew:
		m.log.Debug("[daemon/process/renew] %s: Triggering server renew..", s.ID)
		if err := s.Renew(); err != nil {
			m.log.Error("[daemon/process/renew] %s: Renewing server certificate failed: %s!", s.ID, err.Error())
			return nil, true, err
		}
		return nil, true, nil
	case actionStatus:
		m.log.Debug("[daemon/process/status] %s: Reading server status..", s.ID)
		r, err := s.Status()
		if err != nil {
			m.log.Error("[daemon/process/status] %s: Reading server response failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		var (
			v = typeStatus{PID: s.Pid(), Status: r}
			o []byte
		)
		if o, err = json.Marshal(v); err != nil {
			m.log.Error("[daemon/process/status] %s: Marshaling server response failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		return &message{Action: responseStatus, Data: o}, false, nil
	case actionUpdate:
		v, ok := n.e.(*details)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/edit] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Debug("[daemon/process/edit] %s: Editing server with options [%+v]", s.ID, v)
		if err := v.verify(false); err != nil {
			m.log.Error("[daemon/process/edit] %s: Cannot verify update details: %s!", s.ID, err.Error())
			return nil, false, err
		}
		if err := s.edit(v); err != nil {
			m.log.Error("[daemon/process/edit] %s: Attempting to edit server failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		if !v.Restart {
			return nil, true, nil
		}
		if err := s.Restart(); err != nil {
			m.log.Error("[daemon/process/edit] %s: Attempting to restart server failed: %s!", s.ID, err.Error())
			return nil, true, err
		}
		return nil, true, nil
	case actionRestart:
		m.log.Debug("[daemon/process/restart] %s: Restarting server..", s.ID)
		if err := s.Restart(); err != nil {
			m.log.Error("[daemon/process/restart] %s: Restarting server failed: %s!", s.ID, err.Error())
			return nil, true, err
		}
		return nil, true, nil
	case actionNotifyNew:
		v, ok := n.e.(*typeNotify)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/notify] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Debug(`[daemon/process/notify] %s: Adding notifications of "%s" for email "%s".`, s.ID, v.Action, v.Email)
		if err := s.AddNotify(v.Email, v.Action); err != nil {
			m.log.Error("[daemon/process/notify] %s: Attempting to add notification entry failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		return nil, true, nil
	case actionNotifyList:
		v := typeNotifyList{Notifiers: make([]typeNotify, 0, len(s.Config.Notify))}
		for _, z := range s.Config.Notify {
			v.Notifiers = append(v.Notifiers, typeNotify{Email: z.Email, Action: z.Events.String()})
		}
		o, err := json.Marshal(v)
		if err != nil {
			m.log.Error("[daemon/process/notify] %s: Marshaling server response failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		return &message{Action: responseNotifyList, Data: o}, false, nil
	case actionNotifyDelete:
		v, ok := n.e.(*typeNotify)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/notify] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Debug(`[daemon/process/notify] %s: Removing notifications for email "%s".`, s.ID, v.Email)
		s.RemoveNotify(v.Email)
		return nil, true, nil
	case actionConnect:
		if !s.Running() {
			return nil, false, nil
		}
		v, ok := n.e.(*typeConnect)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/connect] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Trace("[daemon/process/connect] %s: Received a connect message.", s.ID)
		s.ActionConnect(v.Name, v.Local, v.Remote)
		return nil, false, nil
	case actionDisconnect:
		if !s.Running() {
			return nil, false, nil
		}
		v, ok := n.e.(*typeConnect)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/connect] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Trace("[daemon/process/disconnect] %s: Received a disconnect message.", s.ID)
		s.ActionDisconnect(v.Name, v.Local, v.Duration)
		return nil, false, nil
	case actionOptionNew:
		v, ok := n.e.(*typeOption)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/option] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Debug(`[daemon/process/option] %s: Adding server option of "%s".`, s.ID, v.Value)
		s.AddOption(v.Value, v.Push, v.Config)
		return nil, true, nil
	case actionOptionList:
		v := typeOptionList{Options: make([]typeOption, 0, len(s.Config.Options))}
		for _, z := range s.Config.Options {
			v.Options = append(v.Options, typeOption{Push: z.Push, Value: z.Value, Config: z.Client})
		}
		o, err := json.Marshal(v)
		if err != nil {
			m.log.Error("[daemon/process/notify] %s: Marshaling server response failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		return &message{Action: responseOptionList, Data: o}, false, nil
	case actionOptionDelete:
		v, ok := n.e.(*typeOption)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/option] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Debug(`[daemon/process/option] %s: Removing server option of "%s".`, s.ID, v.Value)
		s.RemoveOption(v.Value, v.Push, v.Config)
		return nil, true, nil
	case actionOptionClientNew:
		v, ok := n.e.(*typeOption)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/option] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Debug(`[daemon/process/option] %s: Adding server option of "%s".`, s.ID, v.Value)
		s.AddClientOption(v.Client, v.Value)
		return nil, true, nil
	case actionOptionClientList:
		v := typeOptionList{Options: make([]typeOption, 0, len(s.Service.Clients))}
		for n, c := range s.Service.Clients {
			for i := range c {
				v.Options = append(v.Options, typeOption{Value: c[i], Client: n})
			}
		}
		o, err := json.Marshal(v)
		if err != nil {
			m.log.Error("[daemon/process/notify] %s: Marshaling server response failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		return &message{Action: responseOptionClientList, Data: o}, false, nil
	case actionOptionClientDelete:
		v, ok := n.e.(*typeOption)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/option] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		m.log.Debug(`[daemon/process/option] %s: Removing server option of "%s".`, s.ID, v.Value)
		s.RemoveClientOption(v.Client, v.Value)
		return nil, true, nil

	case actionClientList:
		m.log.Debug("[daemon/process/clientlist] %s: Generating client list..", s.ID)
		c := typeClientList{Clients: make([]string, 0, len(s.CA.Issued))}
		for i := range s.CA.Issued {
			if !s.CA.Issued[i].Valid() {
				continue
			}
			if s.CA.Issued[i].Name == s.Service.Hostname {
				c.Clients = append(c.Clients, s.CA.Issued[i].Name+" (server)")
				continue
			}
			c.Clients = append(c.Clients, s.CA.Issued[i].Name)
		}
		sort.Strings(c.Clients)
		o, err := json.Marshal(c)
		if err != nil {
			m.log.Error("[daemon/process/clientlist] %s: Marshaling server response failed: %s!", s.ID, err.Error())
			return nil, false, err
		}
		return &message{Action: responseClientList, Data: o}, false, nil
	case actionServerDelete:
		v, ok := n.e.(*typeServerDelete)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/deleteserver] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		if m.log.Info("[daemon/process/deleteserver] %s: Deleting server..", s.ID); s.Running() {
			m.log.Debug("[daemon/process/deleteserver] %s: Stopping running server.", s.ID)
			if err := s.Stop(); err != nil {
				m.log.Error("[dameon/process/deleteserver] %s: Stopping server failed: %s!", s.ID, err.Error())
				return nil, false, err
			}
		}
		var err error
		if m.lock.Lock(); !v.Soft {
			if err = os.RemoveAll(s.CA.Directory); err != nil {
				m.log.Error(`[dameon/process/deleteserver] %s: Deleting server CA directory "%s" failed: %s!`, s.ID, s.CA.Directory, err.Error())
			}
			if err = os.Remove(s.file); err != nil {
				m.log.Error(`[dameon/process/deleteserver] %s: Deleting server config file "%s" failed: %s!`, s.ID, s.file, err.Error())
			}
		}
		delete(m.servers, s.ID)
		m.lock.Unlock()
		m.log.Info("[daemon/process/deleteserver] %s: Server deleted!", s.ID)
		return nil, false, err
	case actionClientNew:
		v, ok := n.e.(*typeClientNew)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/newclient] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		if len(v.Name) == 0 {
			return nil, false, xerr.Wrap("name", errNoEmpty)
		}
		m.log.Debug(`[daemon/process/newclient] %s: Creating a new client "%s"..`, s.ID, v.Name)
		r, _, _, err := s.NewClient(v.Name, v.Email, int(v.Days))
		if err != nil {
			m.log.Error(`[daemon/process/newclient] %s: Error creating a new client "%s": %s!`, s.ID, v.Name, err.Error())
			return nil, false, err
		}
		return &message{Action: responseClientNew, Data: r}, false, nil
	case actionClientDelete:
		v, ok := n.e.(*typeClientDelete)
		if !ok || n.e == nil {
			m.log.Error("[daemon/process/deleteclient] %s: Received an invalid message payload!", s.ID)
			return nil, false, errInvalidPayload
		}
		if strings.EqualFold(s.Service.Hostname, v.Name) {
			m.log.Error(`[daemon/process/deleteclient] %s: Cannot revoke server certificate "%s"!`, s.ID, s.Service.Hostname)
			return nil, false, xerr.New(`cannot revoke server certificate "` + s.Service.Hostname + `"`)
		}
		m.log.Info(`[daemon/process/deleteclient] %s: Attempting to remove client "%s"..`, s.ID, v.Name)
		if c := s.CA.Certificate(v.Name); c != nil {
			c.Revoke()
			if err := s.CRL(); err != nil {
				m.log.Warning(`[daemon/process/deleteclient] %s: Could not revoke certificate "%s": %s!`, s.ID, v.Name, err.Error())
				return nil, false, err
			}
			m.log.Debug(`[daemon/process/deleteclient] %s: Client "%s" removed and revoked.`, s.ID, v.Name)
			return nil, true, nil
		}
		m.log.Warning(`[daemon/process/deleteclient] %s: Cannot revoke a non-existent certificate "%s"!`, s.ID, v.Name)
		return nil, false, xerr.New(`certificate "` + v.Name + `" does not exist`)
	}
	m.log.Trace("[daemon/process] Received an invalid message, ignoring!")
	return nil, false, nil
}
