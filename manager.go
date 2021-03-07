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
	"context"
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/PurpleSec/logx"
	"github.com/iDigitalFlame/akcss/vpn"
	"github.com/iDigitalFlame/akcss/xerr"
)

var (
	errNoEmpty        = xerr.New("cannot be empty")
	errInvalidID      = xerr.New("server ID does not exist")
	errInvalidPayload = xerr.New("unexpected client payload")
	errInvalidCountry = xerr.New("country value must be a country code (ex: US, EU, CN)")
)

type manager struct {
	Config struct {
		Log struct {
			Path  string `json:"path,omitempty"`
			Level uint8  `json:"level"`
		} `json:"log"`
		Fail bool `json:"exit_on_error"`
		Dirs struct {
			CA     string `json:"ca"`
			Temp   string `json:"temp,omitempty"`
			Config string `json:"config"`
		} `json:"dirs"`
		Email struct {
			Host     string `json:"host"`
			From     string `json:"sender"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"email"`
		Socket  string `json:"sock,omitempty"`
		Bailout uint8  `json:"bailtime,omitempty"`
	}

	log     logx.Log
	err     error
	lock    sync.RWMutex
	cancel  context.CancelFunc
	startup uint32
	deliver chan mail
	servers map[string]*server
}

func daemon(f string) error {
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return err
	}
	var m manager
	if err = json.Unmarshal(b, &m.Config); err != nil {
		return xerr.Wrap(`unable to parse config "`+f+`"`, err)
	}
	if m.log = logx.Multiple(logx.Console(logx.Level(m.Config.Log.Level))); len(m.Config.Log.Path) > 0 {
		n, err := logx.File(m.Config.Log.Path, logx.Level(m.Config.Log.Level))
		if err != nil {
			return xerr.Wrap(`could not create log "`+m.Config.Log.Path+``, err)
		}
		m.log.(*logx.Multi).Add(n)
	}
	if err = m.reload(); err != nil {
		return err
	}
	if len(m.Config.Socket) == 0 {
		if runtime.GOOS == "windows" {
			m.Config.Socket = socketTCP
		} else {
			m.Config.Socket = socket
		}
	}
	var l net.Listener
	if strings.HasPrefix("unix:", strings.ToLower(m.Config.Socket)) {
		l, err = net.Listen("unix", m.Config.Socket[5:])
	} else {
		l, err = net.Listen("tcp", m.Config.Socket)
	}
	if err != nil {
		return xerr.Wrap(`could not listen on "`+m.Config.Socket+`"`, err)
	}
	if _, ok := l.(*net.UnixListener); ok {
		if err = os.Chmod(m.Config.Socket, 0640); err != nil {
			l.Close()
			m.shutdown(l)
			return xerr.Wrap(`could not set permissions on "`+m.Config.Socket+`"`, err)
		}
	}
	var (
		w = make(chan os.Signal, 1)
		x context.Context
	)
	m.deliver = make(chan mail, 64)
	x, m.cancel = context.WithCancel(context.Background())
	signal.Notify(w, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	m.log.Info("[daemon] Starting up...")
	for k, s := range m.servers {
		if !s.Config.Auto {
			continue
		}
		m.log.Debug("[deamon] Starting server %q...", k)
		if err = s.Start(); err != nil {
			m.shutdown(l)
			return xerr.Wrap(`could not autostart server "`+k+`"`, err)
		}
		m.log.Debug("[daemon] Server %q startup complete.", k)
	}
	y := time.Duration(m.Config.Bailout) * time.Second
	if y <= 0 {
		y = time.Second * 15
	}
	z := time.AfterFunc(y, func() { atomic.StoreUint32(&m.startup, 1) })
	m.log.Info("[daemon] Startup complete! Listening on %q...", m.Config.Socket)
	go m.mailer(x)
	go m.listen(x, l)
	select {
	case <-w:
	case <-x.Done():
	}
	signal.Reset(syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	m.log.Info("[daemon] Shutting down and stopping threads...")
	m.shutdown(l)
	m.cancel()
	z.Stop()
	if len(m.deliver) > 0 {
		m.log.Info("[daemon] Sending queued emails before shutdown...")
		for i := len(m.deliver); i > 0; i = len(m.deliver) {
			e := <-m.deliver
			m.log.Debug("[daemon/mailer] Received email to send to %q...", e.To)
			if err := m.mail(e); err != nil {
				m.log.Warning("[daemon/mailer] Could not send email to %q: %s!", e.To, err.Error())
			}
			m.log.Debug("[daemon/mailer] Completed email request to %q...", e.To)
		}
	}
	close(w)
	close(m.deliver)
	m.log.Info("[daemon] Shutdown complete.")
	return m.err
}
func (m *manager) Dir() string {
	return m.Config.Dirs.Temp
}
func (m *manager) Log() logx.Log {
	return m.log
}
func (m *manager) reload() error {
	if m.log.Debug("[daemon/reload] Reload and server verification started..."); len(m.Config.Dirs.CA) == 0 {
		return xerr.New("certificate directory cannot be empty")
	}
	if len(m.Config.Dirs.Config) == 0 {
		return xerr.New("configuration directory cannot be empty")
	}
	if z, err := os.Stat(m.Config.Dirs.CA); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err = os.MkdirAll(m.Config.Dirs.CA, 0755); err != nil {
			return err
		}
	} else if !z.IsDir() {
		return xerr.New(`invalid certificate directory "` + m.Config.Dirs.CA + `"`)
	}
	if err := os.Chmod(m.Config.Dirs.CA, 0755); err != nil {
		return err
	}
	if z, err := os.Stat(m.Config.Dirs.Config); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err = os.MkdirAll(m.Config.Dirs.Config, 0700); err != nil {
			return err
		}
	} else if !z.IsDir() {
		return xerr.New(`invalid configuration directory "` + m.Config.Dirs.Config + `"`)
	}
	if err := os.Chmod(m.Config.Dirs.Config, 0700); err != nil {
		return err
	}
	if len(m.Config.Dirs.Temp) == 0 {
		m.Config.Dirs.Temp = filepath.Join(os.TempDir(), "akcss")
	}
	if i, err := os.Stat(m.Config.Dirs.Temp); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err = os.MkdirAll(m.Config.Dirs.Temp, 0755); err != nil {
			return err
		}
	} else if !i.IsDir() {
		return xerr.New(`invalid temp directory "` + m.Config.Dirs.Temp + `"`)
	}
	if err := os.Chmod(m.Config.Dirs.Temp, 0755); err != nil {
		return err
	}
	l, err := filepath.Glob(filepath.Join(m.Config.Dirs.Config, "*.conf"))
	if err != nil {
		return xerr.Wrap(`unable to load config "`+m.Config.Dirs.Config+`"`, err)
	}
	if len(l) == 0 {
		if m.log.Debug("[server/reload] No server entries found, bailing!"); m.servers == nil {
			m.servers = make(map[string]*server)
		}
		return nil
	}
	var (
		h  header
		b  []byte
		v  *server
		ok bool
	)
	if m.servers == nil {
		m.servers = make(map[string]*server, len(l))
	}
	m.log.Info("[daemon/reload] Reading %d server entries..", len(l))
	for i := range l {
		m.log.Debug("[daemon/reload] Reading file %q...", l[i])
		if b, err = ioutil.ReadFile(l[i]); err != nil {
			return err
		}
		if err = json.Unmarshal(b, &h); err != nil {
			return xerr.Wrap(`unable to parse "`+l[i]+`"`, err)
		}
		if len(h.ID) == 0 {
			return xerr.New(`invalid server config "` + l[i] + `"`)
		}
		if !valid(h.ID) {
			return xerr.New(`server ID "` + h.ID + `" is invalid`)
		}
		m.log.Debug("[daemon/reload] Found server %q in file %q...", h.ID, l[i])
		if v, ok = m.servers[h.ID]; !ok {
			v = &server{file: l[i]}
			if v.Server, err = vpn.Load(b, m); err != nil {
				return xerr.Wrap(`unable to parse "`+l[i]+`"`, err)
			}
			if !valid(v.ID) {
				return xerr.New(`server ID "` + v.ID + `" is invalid`)
			}
			m.servers[h.ID] = v
			m.log.Debug("[daemon/reload] Server %q has been added from %q!", h.ID, l[i])
			continue
		}
		m.log.Debug("[daemon/reload] Server %q already exists, reloading from %q!", v.ID, l[i])
		if err = v.Server.Reload(b); err != nil {
			return xerr.Wrap(`unable to reload server "`+v.ID+`"`, err)
		}
		if !valid(v.ID) {
			return xerr.New(`server ID "` + v.ID + `" is invalid`)
		}
		m.log.Debug("[daemon/reload] Server %q reload complete.", v.ID)
		if err = v.Save(); err != nil {
			return xerr.Wrap(`unable to save server "`+v.ID+`"`, err)
		}
	}
	m.log.Info("[daemon/reload] Reload complete, %d servers loaded.", len(m.servers))
	return nil
}
func (m *manager) Socket() string {
	return m.Config.Socket
}
func (m *manager) bail(err error) {
	if err == nil {
		return
	}
	m.log.Error("[daemon] Triggering exit due to error: %s!", err.Error())
	m.err = err
	m.cancel()
}
func (m *manager) shutdown(l net.Listener) {
	m.log.Info("[daemon/shutdown] Shutting down server...")
	if err := l.Close(); err != nil {
		m.log.Warning("[daemon/shutdown] Error during listener close: %s!", err.Error())
	}
	if err := os.Remove(m.Config.Socket); err != nil && !os.IsNotExist(err) {
		m.log.Warning("[daemon/shutdown] Error during listener removal: %s!", err.Error())
	}
	for k, s := range m.servers {
		if !s.Running() {
			continue
		}
		m.log.Debug("[daemon/shutdown] Attempting to stop server %q...", k)
		if err := s.Stop(); err != nil {
			if m.err == nil {
				m.err = err
			}
			m.log.Warning("[daemon/shutdown] Error during server %q stop: %s!", k, err.Error())
		}
		m.log.Debug("[daemon/shutdown] Server %q stopped.", k)
		if err := s.Save(); err != nil {
			m.log.Warning("[daemon/shutdown] %s: Saving server state failed: %s!", s.ID, err.Error())
		}
	}
	if m.err != nil {
		m.log.Debug("[daemon/shutdown] Shutdown complete with errors: %s!", m.err.Error())
	} else {
		m.log.Debug("[daemon/shutdown] Shutdown complete.")
	}
}
func (m *manager) Callback(s *vpn.Server, err error) {
	m.log.Debug("[daemon/callback] Received callback from %q, error (%s).", s.ID, err)
	i, ok := m.servers[s.ID]
	if !ok {
		m.log.Warning("[daemon/callback] Received callback from unknown server %q!", s.ID)
	}
	if ok && i != nil {
		if err := i.Save(); err != nil {
			m.log.Error("[daemon/callback] %s: Error saving server: %s!", s.ID, err.Error())
		}
	}
	if err != nil {
		m.log.Error("[daemon/callback] %s: Callback error: %s!", s.ID, err.Error())
		if m.Config.Fail || atomic.LoadUint32(&m.startup) == 0 {
			m.bail(xerr.Wrap(s.ID, err))
		}
	}
}
func (m *manager) accept(x context.Context, c net.Conn) {
	var (
		n   message
		err = n.Read(c)
	)
	if err != nil {
		m.log.Error("[demon/accept] Error during read: %s!", err.Error())
		c.Close()
		return
	}
	m.log.Trace("[demon/accept] Received %q.", n.String())
	r, err := m.process(x, n)
	if err != nil {
		if err = raw(responseError, []byte(err.Error()), c); err != nil {
			m.log.Error("[demon/accept] Error during write: %s!", err.Error())
		}
		c.Close()
		return
	}
	if r == nil {
		err = raw(responseOk, nil, c)
	} else {
		err = r.Write(c)
	}
	if c.Close(); err != nil {
		m.log.Warning("[daemon/accept] Error during write: %s!", err.Error())
	}
}
func (m *manager) listen(x context.Context, l net.Listener) {
	for m.log.Info("[daemon/listen] Starting listening thread..."); ; {
		select {
		case <-x.Done():
			m.log.Info("[daemon/listen] Stopping listening thread...")
			return
		default:
		}
		c, err := l.Accept()
		if err != nil {
			e, ok := err.(net.Error)
			if ok && e.Timeout() {
				continue
			}
			if x.Err() != nil {
				return
			}
			if strings.HasSuffix(err.Error(), ": use of closed network connection") {
				break
			}
			m.log.Error("[daemon/listen] Error occurred during accept: %s!", err.Error())
			if ok && !e.Timeout() && !e.Temporary() {
				break
			}
			continue
		}
		if c == nil {
			continue
		}
		if n, ok := c.(*net.UnixConn); ok {
			var (
				f *os.File
				u *syscall.Ucred
			)
			if f, err = n.File(); err != nil {
				m.log.Error("[daemon/listen] Could not grab file handle of socket: %s!", err.Error())
				c.Close()
				continue
			}
			if u, err = syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED); err != nil {
				m.log.Error("[daemon/listen] Could get file handle peer creds: %s!", err.Error())
				f.Close()
				c.Close()
				continue
			}
			f.Close()
			m.log.Trace("[daemon/listen] Connection established by PID: %d/UID: %d!", u.Pid, u.Uid)
		}
		go m.accept(x, c)
	}
	m.log.Info("[daemon/listen] Stopping listening thread...")
	m.cancel()
}
