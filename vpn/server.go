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

package vpn

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/PurpleSec/logx"
	"github.com/iDigitalFlame/akcss/pki"
	"github.com/iDigitalFlame/akcss/xerr"
)

var (
	errBlocked    = xerr.New("server is blocked on an operaton")
	errRunning    = xerr.New("server is already running")
	errInvalidID  = xerr.New("server ID cannot be empty")
	errNotRunning = xerr.New("server is not running")
)

const (
	debug    = false
	grace    = time.Hour * 24
	timeout  = time.Second * 15
	ipRoute2 = false
)

// Server is a struct that contains the configuration information for a OpenVPN server. This can
// be used to control a running server or start a new one.
type Server struct {
	ID string         `json:"id"`
	CA *pki.Authority `json:"ca"`
	DH struct {
		Size uint16 `json:"size"`
		Data []byte `json:"data,omitempty"`
		File string `json:"file,omitempty"`
	} `json:"dh"`
	Config struct {
		Auto   bool `json:"autostart"`
		Limits struct {
			Max       uint16 `json:"max_clients"`
			KeepAlive struct {
				Timeout  uint16 `json:"timeout"`
				Interval uint16 `json:"interval"`
			} `json:"keep_alive"`
		} `json:"limits"`
		Notify   []notification `json:"notify,omitempty"`
		Options  []option       `json:"options,omitempty"`
		Override struct {
			Client string `json:"client,omitempty"`
			Server string `json:"server,omitempty"`
		} `json:"override"`
	} `json:"config"`
	Network struct {
		Range struct {
			End   string `json:"end,omitempty"`
			Mask  string `json:"mask"`
			Base  string `json:"base"`
			Start string `json:"start,omitempty"`
		} `json:"range"`
		Saved     []string `json:"saved,omitempty"`
		Crosstalk bool     `json:"crosstalk"`
	} `json:"network"`
	Service struct {
		Auth struct {
			File string `json:"file,omitempty"`
			Data []byte `json:"data,omitempty"`
		} `json:"auth"`
		Port     uint16              `json:"port"`
		Clients  map[string][]string `json:"client_config,omitempty"`
		Protocol protocol            `json:"protocol"`
		Hostname string              `json:"hostname"`
	} `json:"server"`

	e       *exec.Cmd
	log     logx.Log
	dir     string
	lock    sync.Mutex
	active  uint32
	cancel  context.CancelFunc
	manager manager
}
type writer interface {
	io.StringWriter
	io.Writer
}
type manager interface {
	Dir() string
	Log() logx.Log
	Socket() string
	Callback(*Server, error)
	Mail(string, string, string)
}

func (s *Server) kill() {
	if atomic.LoadUint32(&s.active) == 0 {
		return
	}
	if s.e == nil {
		return
	}
	s.log.Warning("[server/kill] %s: Force killing process after grace timeout of %s!", s.ID, timeout.String())
	if err := s.e.Process.Kill(); err != nil {
		s.log.Error("[server/kill] %s: Killing process resulted in an error: %s!", s.ID, err.Error())
	}
}
func (s *Server) wait() {
	if s.active == 0 || s.e == nil {
		return
	}
	s.lock.Lock()
	s.log.Trace("[server/wait] %s: Mutex locked and watching server process...", s.ID)
	var err error
	if err = s.e.Wait(); err != nil {
		s.log.Warning("[server/wait] %s: Process exited with error: %s!", s.ID, err.Error())
		if d := lastMessage(filepath.Join(s.dir, "server.log")); len(d) > 0 {
			s.log.Error("[server/wait] %s: Log trace:\n%s", s.ID, d)
		}
	}
	s.log.Trace("[server/wait] %s: Wait ended!", s.ID)
	if b, err := ioutil.ReadFile(filepath.Join(s.dir, "ip.log")); err == nil {
		var (
			i int
			x = strings.Split(string(b), "\n")
		)
		for s.Network.Saved = make([]string, 0, len(x)); i < len(x); i++ {
			if len(x[i]) == 0 {
				continue
			}
			s.Network.Saved = append(s.Network.Saved, x[i])
		}
		s.log.Trace("[server/wait] %s: Saved %d IP state entries.", s.ID, len(s.Network.Saved))
	} else {
		s.log.Warning("[server/wait] %s: Could not save IP state entries: %s!", s.ID, err.Error())
	}
	if !debug {
		if err := os.RemoveAll(s.dir); err != nil {
			s.log.Warning("[server/wait] %s: Could not remove server directory %q: %s!", s.ID, s.dir, err.Error())
		}
	}
	atomic.StoreUint32(&s.active, 0)
	s.lock.Unlock()
	s.manager.Callback(s, err)
}

// CRL will attempt to generate the CRL file for this Server. This will also send any emails for notifications that
// are configured.
func (s *Server) CRL() error {
	return s.crl(false, true, "")
}

// Stop will gracefull stop the server and save any stored IP options in the struct. This will also remove the server
// runtime directory.
func (s *Server) Stop() error {
	return s.stop(true)
}

// Pid returns the Server process ID. If the server is not running, this function returns zero.
func (s *Server) Pid() uint64 {
	if atomic.LoadUint32(&s.active) == 0 || s.e == nil || s.e.Process == nil {
		return 0
	}
	return uint64(s.e.Process.Pid)
}
func (s *Server) start() error {
	switch atomic.LoadUint32(&s.active) {
	case 1:
		return nil
	case 2:
		return errBlocked
	}
	s.log.Trace("[server/start] %s: Trying to get lock..", s.ID)
	s.lock.Lock()
	s.log.Trace("[server/start] %s: Got lock!", s.ID)
	defer s.lock.Unlock()
	var x context.Context
	x, s.cancel = context.WithCancel(context.Background())
	if b, err := s.prep(x, true); b && err == nil {
		s.log.Info("[server/start] %s: Server is blocked on an operation, will start once complete. Handing back control flow.", s.ID)
		return nil
	} else if s.cancel(); err != nil {
		return err
	}
	var (
		t      = filepath.Join(s.dir, "ip.log")
		c      = filepath.Join(s.dir, "client-config")
		p, err = os.Executable()
	)
	if s.cancel = nil; err != nil {
		return xerr.Wrap("unable to get binary path", err)
	}
	o, err := loadOverride(s.Config.Override.Server)
	if err != nil {
		return xerr.Wrap(`unable to load server override "`+s.Config.Override.Server+`"`, err)
	}
	if err = os.MkdirAll(c, 0750); err != nil {
		return err
	}
	if err = s.writeConfigs(c); err != nil {
		return err
	}
	f, err := os.OpenFile(t, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return xerr.Wrap(`could not open ip table "`+t+`"`, err)
	}
	for i := range s.Network.Saved {
		s.log.Debug("[server/start] %s: Writing IP table setting %q...", s.ID, s.Network.Saved[i])
		if _, err = f.WriteString(s.Network.Saved[i] + "\n"); err != nil {
			break
		}
	}
	if err := f.Close(); err != nil {
		return xerr.Wrap(`could not close ip table "`+t+`"`, err)
	}
	if err != nil {
		return xerr.Wrap(`could not write ip table "`+t+`"`, err)
	}
	r := s.CA.Certificate(s.Service.Hostname)
	if r == nil {
		s.log.Info("[server/start] %s: Certificate for %q not found, generating now...", s.ID, s.Service.Hostname)
		if r, err = s.CA.CreateServer(s.Service.Hostname, "", 0); err != nil {
			return xerr.Wrap("could not generate server certificate", err)
		}
	}
	i := filepath.Join(s.dir, "server.conf")
	if err = s.writeFile(o, r, i, t, c, p); err != nil {
		return err
	}
	s.log.Debug("[server/start] %s: Setting working directory permissions...", s.ID)
	if err = filepath.Walk(s.dir, perms); err != nil {
		s.log.Warning("[server/start] %s: Could not properly set permissions: %s!", s.ID, err.Error())
	}
	s.e = exec.Command("openvpn", "--config", i)
	if err = s.e.Start(); err != nil {
		return xerr.Wrap("could not start server", err)
	}
	atomic.StoreUint32(&s.active, 1)
	s.log.Info("[server/start] %s: Started openvpn process, PID %d..", s.ID, s.Pid())
	go s.wait()
	return nil
}

// Start will begin the process of creating the server directory, generating the server config and starting the
// primary server process.
func (s *Server) Start() error {
	if atomic.LoadUint32(&s.active) > 0 {
		return errRunning
	}
	if err := s.crl(true, true, ""); err != nil {
		return err
	}
	if err := s.start(); err != nil {
		return err
	}
	s.actionStart()
	return nil
}

// Renew will attempt to renew the Server's certificate.
func (s *Server) Renew() error {
	return s.renew("")
}

// Running returns true if the server is currently active.
func (s *Server) Running() bool {
	return atomic.LoadUint32(&s.active) > 0
}

// Print will write the server details to the specified writer.
func (s *Server) Print(w writer) {
	w.WriteString("Server " + s.ID + "\n\n")
	w.WriteString(exp("Auto Start", 20))
	if s.Config.Auto {
		w.WriteString("Yes\n")
	} else {
		w.WriteString("No\n")
	}
	w.WriteString(exp("Hostname", 20) + s.Service.Hostname + "\n")
	w.WriteString(exp("Max Clients", 20))
	w.WriteString(strconv.FormatUint(uint64(s.Config.Limits.Max), 10) + "\n")
	w.WriteString("\nKeep Alive\n  " + exp("Timeout", 18))
	w.WriteString(strconv.FormatUint(uint64(s.Config.Limits.KeepAlive.Timeout), 10) + "\n")
	w.WriteString("  " + exp("Interval", 18))
	w.WriteString(strconv.FormatUint(uint64(s.Config.Limits.KeepAlive.Interval), 10) + "\n")
	w.WriteString("\nConfig Overrides\n  " + exp("Client", 18) + s.Config.Override.Client + "\n")
	w.WriteString("  " + exp("Server", 18) + s.Config.Override.Server + "\n")
	w.WriteString("\nNetwork\n  " + exp("Port", 18))
	w.WriteString(strconv.FormatUint(uint64(s.Service.Port), 10) + "/" + s.Service.Protocol.String() + "\n")
	if len(s.Network.Range.Start) > 0 && len(s.Network.Range.End) > 0 {
		w.WriteString("  " + exp("Range", 18) + s.Network.Range.Start + " - " + s.Network.Range.End + "\n")
	} else {
		w.WriteString("  " + exp("Range", 18) + s.Network.Range.Base + "\n")
	}
	w.WriteString("  " + exp("Range Mask", 18) + s.Network.Range.Mask + "\n")
	w.WriteString("  " + exp("Crosstalk", 18))
	if s.Network.Crosstalk {
		w.WriteString("Yes\n")
	} else {
		w.WriteString("No\n")
	}
	w.WriteString("\nIssuer\n  " + exp("Street", 18) + s.CA.Subject.Street + "\n")
	w.WriteString("  " + exp("City", 18) + s.CA.Subject.City + "\n")
	w.WriteString("  " + exp("State", 18) + s.CA.Subject.State + "\n")
	w.WriteString("  " + exp("ZIP", 18) + s.CA.Subject.ZIP + "\n")
	w.WriteString("  " + exp("Country", 18) + s.CA.Subject.Country + "\n")
	w.WriteString("  " + exp("Department", 18) + s.CA.Subject.Department + "\n")
	w.WriteString("  " + exp("Organization", 18) + s.CA.Subject.Organization + "\n")
	w.WriteString("  " + exp("Domain", 18) + s.CA.Subject.Domain + "\n")
	w.WriteString("  " + exp("Email", 18) + s.CA.Subject.Email + "\n")
	if len(s.Config.Options) > 0 {
		w.WriteString("\nOptions\n")
		for _, x := range s.Config.Options {
			switch {
			case x.Client && x.Push:
				w.WriteString("[client|push] ")
			case x.Client:
				w.WriteString("[client] ")
			case x.Push:
				w.WriteString("[push] ")
			}
			w.WriteString(x.Value + "\n")
		}
	}
	if len(s.Service.Clients) > 0 {
		w.WriteString("\nClient Options\n")
		for k, v := range s.Service.Clients {
			w.WriteString("  " + k + "\n")
			for _, x := range v {
				w.WriteString("    " + x + "\n")
			}
		}
	}
	if len(s.Config.Notify) > 0 {
		w.WriteString("\nNotifications\n")
		for _, x := range s.Config.Notify {
			w.WriteString("  " + exp(x.Email, 18) + x.Events.String() + "\n")
		}
	}
	w.WriteString("\nPKI\n  " + exp("Cert Life", 18))
	w.WriteString(strconv.FormatUint(uint64(s.CA.Lifetime.Server), 10) + " days\n  ")
	w.WriteString(exp("Issued", 18) + strconv.FormatUint(uint64(len(s.CA.Issued)), 10) + "\n")
	w.WriteString("  " + exp("CA", 18) + s.CA.File() + "\n")
	if c := s.CA.Certificate(s.Service.Hostname); c != nil {
		w.WriteString("  " + exp("Server Cert", 18) + c.File + "\n")
	}
	if len(s.DH.File) > 0 {
		w.WriteString(exp("\nDH Params", 18) + s.DH.File + "\n")
	} else {
		w.WriteString("\nDH Params (gen-size " + strconv.FormatUint(uint64(s.DH.Size), 10) + ")\n")
		if len(s.DH.Data) > 0 {
			w.Write(s.DH.Data)
		}
		if s.DH.Data[len(s.DH.Data)-1] != 10 {
			w.WriteString("\n")
		}
	}
	if len(s.Service.Auth.File) > 0 {
		w.WriteString("  " + exp("\nTLS Auth", 18) + s.Service.Auth.File + "\n")
	} else if len(s.Service.Auth.Data) > 0 {
		w.WriteString("\nTLS Auth\n")
		w.Write(s.Service.Auth.Data)
		if s.Service.Auth.Data[len(s.Service.Auth.Data)-1] != 10 {
			w.WriteString("\n")
		}
	}
	if len(s.Network.Saved) > 0 {
		w.WriteString("\nIP Entries\n")
		for _, x := range s.Network.Saved {
			l := strings.SplitN(x, ",", 3)
			if len(l) < 2 {
				continue
			}
			w.WriteString("  " + l[0] + ": " + l[1] + "\n")
		}
	}
}

// Restart will gracefull stop the server and save any stored IP options in the struct. Once complete, this function
// will regenerate the server configuration files and will start up the server.
func (s *Server) Restart() error {
	i := atomic.LoadUint32(&s.active)
	if i == 2 {
		return errBlocked
	}
	s.log.Debug("[server/restart] %s: Performing a restart...", s.ID)
	if i == 1 {
		if err := s.stop(false); err != nil {
			return err
		}
	}
	return s.start()
}
func (s *Server) stop(n bool) error {
	i := atomic.LoadUint32(&s.active)
	if i == 2 && s.cancel != nil {
		s.cancel()
		s.lock.Lock()
		s.cancel = nil
		s.lock.Unlock()
		return nil
	}
	if i == 0 {
		return errNotRunning
	}
	s.log.Info("[server/stop] %s: Stopping server..", s.ID)
	var (
		t   = time.AfterFunc(timeout, s.kill)
		err = s.e.Process.Signal(syscall.SIGINT)
	)
	s.log.Debug("[server/stop] %s: Sent SIGINT..", s.ID)
	if err != nil {
		if err == os.ErrProcessDone {
			err = nil
		} else {
			s.log.Warning("[server/stop] %s: Sending stop singal failed: %s!", s.ID, err.Error())
		}
	}
	s.log.Debug("[server/stop] %s: Waiting for process to complete.", s.ID)
	s.lock.Lock()
	if !t.Stop() {
		<-t.C
	}
	s.log.Debug("[server/stop] %s: Stop complete.", s.ID)
	if s.lock.Unlock(); n {
		s.actionStop()
	}
	return err
}

func (s *Server) renew(h string) error {
	r := atomic.LoadUint32(&s.active)
	if r == 2 {
		return errBlocked
	}
	s.log.Debug("[server/renew] %s: Starting the renew process...", s.ID)
	if r == 1 {
		s.log.Info("[server/renew] %s: Stopping active server instance...", s.ID)
		if err := s.stop(false); err != nil {
			return err
		}
		s.log.Debug("[server/renew] %s: Stop done.", s.ID)
	}
	var c *pki.Certificate
	if s.lock.Lock(); len(h) > 0 {
		c = s.CA.Certificate(h)
		s.log.Info("[server/renew] %s: Updating certificate to match new hostname (%s => %s)...", s.ID, h, s.Service.Hostname)
	} else {
		c = s.CA.Certificate(s.Service.Hostname)
		s.log.Debug("[server/renew] %s: Renewing certificate for %q...", s.ID, s.Service.Hostname)
	}
	if c != nil {
		s.log.Info("[server/renew] %s: Revoking certificate %q...", s.ID, c.Serial.String())
		c.Revoke()
	}
	if err := s.crl(true, false, h); err != nil {
		s.lock.Unlock()
		return err
	}
	if _, err := s.CA.CreateServer(s.Service.Hostname, "", 0); err != nil {
		s.lock.Unlock()
		return err
	}
	s.log.Debug("[server/renew] %s: Renew complete!", s.ID)
	if s.actionRenew(); r == 0 {
		s.lock.Unlock()
		return nil
	}
	s.log.Debug("[server/renew] %s: Re-starting server now..", s.ID)
	s.lock.Unlock()
	return s.start()
}

// Reload will update the Server's info with the new data supplied. This function will trigger a certificate renew
// if the hostname changes.
func (s *Server) Reload(b []byte) error {
	if atomic.LoadUint32(&s.active) == 2 {
		return errBlocked
	}
	o := s.Service.Hostname
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if !strings.EqualFold(s.Service.Hostname, o) {
		return s.renew(o)
	}
	if atomic.LoadUint32(&s.active) == 1 {
		return s.Restart()
	}
	return nil
}

// Init is a function only to called on a newly created server instance. This sets up the un-exported
// properties of the struct. This function returns the server instance.
func (s *Server) Init(m manager) *Server {
	s.dir, s.log, s.manager = filepath.Join(m.Dir(), s.ID), m.Log(), m
	s.Service.Hostname = parseName(s.Service.Hostname)
	return s
}

// ChangeName will attempt to renew the Server's certificate with a new hostname.
func (s *Server) ChangeName(n string) error {
	if strings.EqualFold(n, s.Service.Hostname) {
		return nil
	}
	if c := s.CA.Certificate(n); c != nil {
		return xerr.New(`certificate "` + n + `" already exists`)
	}
	o := s.Service.Hostname
	s.Service.Hostname = parseName(n)
	return s.renew(o)
}

// Status will return an array of connected clients and some basic info, such as how long connected and local/remote
// IP addresses.
func (s *Server) Status() ([]Status, error) {
	if i := atomic.LoadUint32(&s.active); i == 0 {
		return nil, errNotRunning
	} else if i == 2 {
		return nil, nil
	}
	b, err := ioutil.ReadFile(filepath.Join(s.dir, "status.log"))
	if err != nil {
		return nil, err
	}
	var (
		v = strings.Split(string(b), "\n")
		r []Status
		w []string
		x int64
	)
	if len(v) == 0 {
		return r, nil
	}
	for i := range v {
		if len(v[i]) < 12 {
			continue
		}
		if v[i][0:12] != "CLIENT_LIST," {
			continue
		}
		if w = strings.Split(v[i], ","); len(w) < 13 {
			continue
		}
		if x, err = strconv.ParseInt(w[8], 10, 64); err != nil {
			break
		}
		if n := strings.IndexByte(w[2], ':'); n > 0 && n < len(w[2]) {
			w[2] = w[2][0:n]
		}
		r = append(r, Status{Name: w[1], Start: time.Unix(x, 0), Local: w[3], Remote: w[2], Cipher: w[12]})
	}
	return r, err
}

// RemoveNotify will remove the email address associated with any notification events, if it exists.
func (s *Server) RemoveNotify(email string) {
	var (
		l = make([]notification, 0, len(s.Config.Notify))
		e = strings.ToLower(strings.TrimSpace(email))
	)
	for i := range s.Config.Notify {
		if s.Config.Notify[i].Email == e {
			continue
		}
		l = append(l, s.Config.Notify[i])
	}
	s.Config.Notify = l
}
func (s *Server) writeConfigs(c string) error {
	for k, v := range s.Service.Clients {
		if len(v) == 0 {
			continue
		}
		k = parseName(k)
		f, err := os.OpenFile(filepath.Join(c, k), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
		if err != nil {
			return xerr.Wrap(`could not open client "`+k+`"`, err)
		}
		for i := range v {
			if _, err = f.WriteString(v[i] + "\n"); err != nil {
				break
			}
		}
		if err := f.Close(); err != nil {
			return xerr.Wrap(`could not close client "`+k+`"`, err)
		}
		if err != nil {
			return xerr.Wrap(`could not write client "`+k+`"`, err)
		}
		os.Chmod(filepath.Join(c, k), 0640)
		s.log.Debug("[server/configs] %s: Wrote client config for %q to %q...", s.ID, k, c)
	}
	return filepath.Walk(s.dir, perms)
}
func (s *Server) notify(a action, m, d string) {
	for i := range s.Config.Notify {
		if s.Config.Notify[i].Events&a == 0 {
			continue
		}
		s.log.Debug("[server/notify] %s: Sending email %q to %q...", s.ID, m, s.Config.Notify[i].Email)
		s.manager.Mail(s.Config.Notify[i].Email, m, d)
	}
}

// Load will create and setup the initial properties of a Server struct from the provided arguments and the
// data contained in the JSON byte array. This function returns any errors made during reading/parsing.
func Load(b []byte, m manager) (*Server, error) {
	var s Server
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	s.dir, s.log, s.manager = filepath.Join(m.Dir(), s.ID), m.Log(), m
	return &s, nil
}
func (s *Server) crl(z, u bool, h string) error {
	if atomic.LoadUint32(&s.active) == 2 {
		return errBlocked
	}
	s.log.Debug("[server/crl] %s: Generation started...", s.ID)
	r, err := s.CA.Update()
	if err != nil {
		return err
	}
	var (
		k    bool
		e, x string
	)
	for i := range r {
		if strings.EqualFold(r[i].Name, s.Service.Hostname) && u {
			s.log.Info("[server/crl] %s: Server certificate (%s) has expired, triggering a renew!", s.ID, r[i].Name)
			k = true
		}
		if r[i].Expired {
			e += r[i].Name + "\n"
			s.actionExpire(r[i].Name)
			s.log.Info("[server/crl] %s: Certificate %q has expired!", s.ID, r[i].Name)
			continue
		}
		if !(z && !u && len(r[i].Name) == len(h) && strings.EqualFold(r[i].Name, h)) {
			x += r[i].Name + "\n"
			s.actionRevoke(r[i].Name)
		}
		s.log.Info("[server/crl] %s: Certificate %q was revoked!", s.ID, r[i].Name)
	}
	var o string
	if len(e) > 0 {
		o = "\n\nThe following entries have expired:\n" + e + "\n\n"
	}
	if len(x) > 0 {
		o += "\n\nThe following entries have been revoked:\n" + x + "\n\n"
	}
	if !z {
		s.actionCRL(o)
	}
	if s.log.Debug("[server/crl] %s: Generation complete.", s.ID); u && k {
		s.log.Info("[server/crl] %s: Server certificate has expired or was revoked, renewing!", s.ID)
		return s.renew("")
	} else if u {
		if c := s.CA.Certificate(s.Service.Hostname); c == nil || !c.ValidFor(grace) {
			s.log.Info("[server/crl] %s: Server certificate is invalid or within renew grace period, renewing!", s.ID)
			return s.renew("")
		}
	}
	return nil
}
func generateAuth(x context.Context) ([]byte, error) {
	o, err := exec.CommandContext(x, "openvpn", "--genkey", "tls-crypt-v2-server").Output()
	if err != nil {
		return nil, err
	}
	if len(o) > 0 && o[len(o)-1] == 10 {
		return o[:len(o)-1], nil
	}
	return o, nil
}
func (s *Server) generateDH(x context.Context, z bool) {
	s.log.Trace("[server/gendh] %s: Trying to get lock..", s.ID)
	s.lock.Lock()
	atomic.StoreUint32(&s.active, 2)
	s.log.Trace("[server/gendh] %s: Got lock!", s.ID)
	var err error
	switch s.DH.Size {
	case 0:
		s.log.Info("[server/gendh] %s: Skipping DHParam generation as the size is zero.", s.ID)
	case 2048, 4096:
		s.log.Info("[server/gendh] %s: Generating DHParams data (size %d), this will take some time...", s.ID, s.DH.Size)
		s.DH.Data, err = exec.CommandContext(x, "openssl", "dhparam", "-2", strconv.FormatUint(uint64(s.DH.Size), 10)).Output()
		if err == nil && len(s.DH.Data) > 0 && s.DH.Data[len(s.DH.Data)-1] == 10 {
			s.DH.Data = s.DH.Data[:len(s.DH.Data)-1]
		}
	default:
		err = xerr.New(`invalid dhparam size "` + strconv.FormatUint(uint64(s.DH.Size), 10) + `"`)
	}
	if err != nil {
		s.log.Error("[server/gendh] %s: Error generating DHParams: %s!", s.ID, err.Error())
		s.manager.Callback(s, err)
	} else {
		s.log.Info("[server/gendh] %s: DHParam generation complete!", s.ID)
	}
	if atomic.StoreUint32(&s.active, 0); err != nil {
		return
	}
	if z {
		s.log.Debug("[server/gendh] %s: Triggering pending server start!", s.ID)
		s.start()
	}
}

// AddNotify will add the email address to the server to be notified on the supplied events. This function
// returns an error if the event names are not valid. Empty events are considered to be "all".
func (s *Server) AddNotify(email, events string) error {
	var (
		a    action
		v    string
		p    action
		e    = strings.ToLower(strings.TrimSpace(email))
		err  error
		x, l int
	)
	if len(events) > 0 {
		for {
			if l = strings.IndexByte(events[x:], ','); l == -1 {
				v = events[x:]
			} else {
				l += x
				v = events[x:l]
			}
			if p, err = parse(v); err != nil {
				return err
			}
			a |= p
			if x = l + 1; l <= 0 || l > len(events) {
				break
			}
		}
	} else {
		a = actionAll
	}
	for i := range s.Config.Notify {
		if s.Config.Notify[i].Email != e {
			continue
		}
		s.Config.Notify[i].Events |= a
		return nil
	}
	s.Config.Notify = append(s.Config.Notify, notification{Email: e, Events: a})
	return nil
}

// AddOption will add the server option value to appear in the generated configuration files and profiles.
// The push option will add the option as a "push" value and config will add the value to each newly generated
// client profile. The changes will be applied on a server restart.
func (s *Server) AddOption(value string, push, config bool) {
	for _, x := range s.Config.Options {
		if x.Value == value && x.Push == push && x.Client == config {
			return
		}
	}
	s.Config.Options = append(s.Config.Options, option{Value: strings.TrimSpace(value), Push: push, Client: config})
}

// AddClientOption will add the specified value into a client specific config for the server. The changes will be
// effective immediately and do NOT require a server restart.
func (s *Server) AddClientOption(client, value string) error {
	var (
		n = strings.ToLower(strings.TrimSpace(parseName(client)))
		c []string
	)
	if s.Service.Clients == nil {
		s.Service.Clients = make(map[string][]string, 1)
	} else {
		c = s.Service.Clients[n]
	}
	for i := range c {
		if c[i] == value {
			return nil
		}
	}
	s.Service.Clients[n] = append(c, strings.TrimSpace(value))
	if err := s.writeConfigs(filepath.Join(s.dir, "client-config")); err != nil {
		return err
	}
	return nil
}
func (s *Server) prep(x context.Context, z bool) (bool, error) {
	if len(s.ID) == 0 {
		return false, errInvalidID
	}
	if s.CA == nil {
		return false, xerr.New(`server "` + s.ID + `" lacks a valid CA store`)
	}
	var err error
	if s.log.Info("[server/prep] %s: Prepping and verifying server settings...", s.ID); len(s.Service.Auth.Data) == 0 {
		s.log.Warning("[server/prep] %s: Auth section is empty, generating new TLS-AUTH key!", s.ID)
		if len(s.Service.Auth.File) == 0 {
			if s.Service.Auth.Data, err = generateAuth(x); err != nil {
				return false, err
			}
		} else {
			i, err := os.Stat(s.Service.Auth.File)
			if err != nil {
				return false, xerr.Wrap(`cannot access auth path "`+s.Service.Auth.File+`"`, err)
			}
			if i.IsDir() {
				return false, xerr.New(`invalid auth path "` + s.Service.Auth.File + `"`)
			}
		}
	}
	if s.DH.Size == 0 {
		s.log.Info("[server/prep] %s: Skipping DH prep as size is zero.", s.ID)
	} else if len(s.DH.Data) == 0 {
		if len(s.DH.File) == 0 {
			atomic.StoreUint32(&s.active, 2)
			go s.generateDH(x, z)
			return true, nil
		}
		i, err := os.Stat(s.DH.File)
		if err != nil {
			return false, xerr.Wrap(`cannot access dhparam path "`+s.DH.File+`"`, err)
		}
		if i.IsDir() {
			return false, xerr.New(`invalid dhparam path "` + s.DH.File + `"`)
		}
	}
	if s.Service.Port == 0 {
		s.log.Warning("[server/prep] %s: Server port is empty, setting to 443!", s.ID)
		s.Service.Port = 443
	}
	if len(s.Service.Hostname) == 0 {
		if h, err := os.Hostname(); err == nil {
			s.Service.Hostname = parseName(h)
		} else {
			s.Service.Hostname = s.ID + "-server"
		}
		s.log.Warning("[server/prep] %s: No hostname given, setting to %q!", s.ID, s.Service.Hostname)
	}
	if s.Config.Limits.Max == 0 {
		s.log.Warning("[server/prep] %s: Client limit is empty, setting to 64!", s.ID)
		s.Config.Limits.Max = 64
	}
	if s.Config.Limits.KeepAlive.Timeout == 0 {
		s.log.Warning("[server/prep] %s: KeepAlive timeout is empty, setting to 120 seconds", s.ID)
		s.Config.Limits.KeepAlive.Timeout = 120
	}
	if s.Config.Limits.KeepAlive.Interval == 0 {
		s.log.Warning("[server/prep] %s: KeepAlive interval is empty, setting to 10!", s.ID)
		s.Config.Limits.KeepAlive.Interval = 10
	}
	if len(s.Network.Range.Base) == 0 && len(s.Network.Range.Start) == 0 && len(s.Network.Range.End) == 0 {
		s.log.Warning(`[server/prep] %s: Network range is empty, setting to "10.10.0.0"!`, s.ID)
		s.Network.Range.Base = "10.10.0.0"
	}
	if len(s.Network.Range.Mask) == 0 {
		s.log.Warning(`[server/prep] %s: Network mask is empty, setting to "255.255.255.0" (%s/24)!`, s.ID, s.Network.Range.Base)
		s.Network.Range.Mask = "255.255.255.0"
	}
	return false, nil
}

// RemoveOption will attempt to remove the specified option value from the server. This function will need to match
// the original push and config values in order to remove the correct option.
func (s *Server) RemoveOption(value string, push, config bool) {
	var (
		l = make([]option, 0, len(s.Config.Options))
		v = strings.TrimSpace(value)
	)
	for _, x := range s.Config.Options {
		if x.Value == v && x.Push == push && x.Client == config {
			continue
		}
		l = append(l, x)
	}
	s.Config.Options = l
}

// RemoveClientOption will remove the specified value from a client specific config for the server. The changes will be
// effective immediately and do NOT require a server restart.
func (s *Server) RemoveClientOption(client, value string) error {
	var (
		n     = strings.ToLower(strings.TrimSpace(parseName(client)))
		c, ok = s.Service.Clients[n]
	)
	if !ok || len(c) == 0 {
		return nil
	}
	l := make([]string, 0, len(c))
	for i := range c {
		if c[i] == value {
			continue
		}
		l = append(l, c[i])
	}
	if len(l) == 0 {
		delete(s.Service.Clients, n)
	} else {
		s.Service.Clients[n] = l
	}
	if err := s.writeConfigs(filepath.Join(s.dir, "client-config")); err != nil {
		return err
	}
	return nil
}
func (s *Server) profile(c *pki.Certificate, p []byte) ([]byte, error) {
	o, err := loadOverride(s.Config.Override.Client)
	if err != nil {
		return nil, xerr.Wrap(`unable to load client override "`+s.Config.Override.Client+`"`, err)
	}
	var (
		d     = []string{"client"}
		u     = o.Get(s, "proto", s.Service.Protocol.String())
		y, z  = o["ipv6"]
		_, z1 = o["noipv6"]
		_, z2 = o["no6"]
	)
	if len(u) > 0 {
		d = append(d, u)
		if ((z && !y.Unset) || !z) && !z1 && !z2 {
			d = append(d, u+"6")
		}
	}
	d = append(d, []string{
		o.Get(s, "dev", "tun"),
		o.Get(s, "remote", s.Service.Hostname+" "+strconv.FormatUint(uint64(s.Service.Port), 10)),
		"script-security 0",
		o.Get(s, "remote-cert-tls", "server"),
		o.Get(s, "remote-cert-eku", `"TLS Web Server Authentication"`),
		o.Get(s, "resolv-retry", "30"),
		o.Get(s, "verb", "2"),
		o.Get(s, "auth", "SHA512"),
		o.Get(s, "auth-nocache", ""),
		o.Get(s, "reneg-sec", "3600"),
		o.Get(s, "user", "nobody"),
		o.Get(s, "group", "nobody"),
		o.Get(s, "persist-key", ""),
		o.Get(s, "persist-tun", ""),
		o.Get(s, "nobind", ""),
		o.Get(s, "allow-compression", "no"),
		o.Get(s, "fast-io", ""),
		o.Get(s, "key-direction", "1"),
		o.Get(s, "verify-x509-name", s.Service.Hostname+" name"),
		o.Get(s, "tun-mtu", "1500"),
		o.Get(s, "cipher", "AES-256-GCM"),
		o.Get(s, "data-ciphers", "AES-256-GCM:AES-256-CBC:CAMELLIA-256-CBC:AES-128-GCM"),
		o.Get(s, "tls-version-min", "1.2"),
		o.Get(s, "tls-ciphersuites", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"),
		o.Get(
			s, "tls-cipher", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:"+
				"TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:"+
				"TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
		),
		o.Get(s, "tls-groups", "X25519:secp256r1:X448:secp521r1:secp384r1"),
	}...)
	if ipRoute2 {
		d = append(d, o.Get(s, "enable-iproute2", ""))
	}
	b := builders.Get().(*bytes.Buffer)
	for i := range d {
		if len(d[i]) == 0 {
			continue
		}
		b.WriteString(d[i] + "\n")
	}
	for _, x := range s.Config.Options {
		if !x.Client {
			continue
		}
		b.WriteString(x.Value + "\n")
	}
	b.WriteString("<ca>\n")
	if err := s.CA.Write(b); err != nil {
		b.Reset()
		builders.Put(b)
		return nil, xerr.Wrap("could not write CA", err)
	}
	b.WriteString("</ca>\n<cert>\n")
	if err := c.Write(b); err != nil {
		b.Reset()
		builders.Put(b)
		return nil, xerr.Wrap("could not write certificate", err)
	}
	b.WriteString("</cert>\n<key>\n")
	if err := c.WriteKey(b); err != nil {
		b.Reset()
		builders.Put(b)
		return nil, xerr.Wrap("could not write private key", err)
	}
	b.WriteString("</key>\n<tls-crypt-v2>\n")
	b.Write(p)
	b.WriteString("</tls-crypt-v2>\n")
	r := b.Bytes()
	b.Reset()
	builders.Put(b)
	return r, nil
}
func (s *Server) writeFile(o override, m *pki.Certificate, p, t, c, e string) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0400)
	if err != nil {
		return xerr.Wrap(`cannot open "`+p+`"`, err)
	}
	var (
		d = []string{
			"mode server",
			o.Get(s, "port", strconv.FormatUint(uint64(s.Service.Port), 10)),
		}
		y, z  = o["ipv6"]
		_, z1 = o["noipv6"]
		_, z2 = o["no6"]
	)
	if s.Service.Protocol == TCP {
		d = append(d, "proto tcp-server")
		if ((z && !y.Unset) || !z) && !z1 && !z2 {
			d = append(d, "proto tcp6-server")
		}
	} else {
		d = append(d, "proto udp")
		if ((z && !y.Unset) || !z) && !z1 && !z2 {
			d = append(d, "proto udp6")
		}
	}
	d = append(d, []string{
		o.Get(s, "dev", "tun"),
		o.Get(s, "ca", s.CA.File()),
		o.Get(s, "cert", m.File),
		o.Get(s, "key", m.Key),
		o.Get(s, "crl-verify", filepath.Join(s.CA.Directory, "crl.pem")),
	}...)
	for i := range d {
		if len(d[i]) == 0 {
			continue
		}
		if _, err = f.WriteString(d[i] + "\n"); err != nil {
			break
		}
	}
	if err != nil {
		f.Close()
		return xerr.Wrap(`cannot write to "`+p+`"`, err)
	}
	if len(s.DH.File) > 0 {
		d = append(d, o.Get(s, "dh", s.DH.File))
	} else if len(s.DH.Data) > 0 {
		if _, err = f.WriteString("<dh>\n"); err != nil {
			f.Close()
			return xerr.Wrap(`cannot write dhparam to "`+p+`"`, err)
		}
		if _, err = f.Write(s.DH.Data); err != nil {
			f.Close()
			return xerr.Wrap(`cannot write dhparam to "`+p+`"`, err)
		}
		if _, err = f.WriteString("\n</dh>\n"); err != nil {
			f.Close()
			return xerr.Wrap(`cannot write dhparam to "`+p+`"`, err)
		}
	} else {
		d = append(d, o.Get(s, "dh", "none"))
	}
	if len(s.Network.Range.Start) > 0 && len(s.Network.Range.End) > 0 {
		d = append(d, o.Get(s, "ifconfig-pool", s.Network.Range.Start+" "+s.Network.Range.End+" "+s.Network.Range.Mask))
	} else {
		d = append(d, o.Get(s, "server", s.Network.Range.Base+" "+s.Network.Range.Mask))
	}
	d = append(d, []string{
		o.Get(s, "topology", "subnet"),
		o.Get(s, "ifconfig-pool-persist", t),
		o.Get(s, "client-config-dir", c),
		"script-security 2",
		`client-connect "` + e + ` --il ` + s.ID + ` c ` + s.manager.Socket() + `"`,
		`client-disconnect "` + e + ` --il ` + s.ID + ` d ` + s.manager.Socket() + `"`,
		o.Get(s, "log", filepath.Join(s.dir, "server.log")),
		o.Get(s, "verb", "2"),
		o.Get(s, "status", filepath.Join(s.dir, "status.log")),
		o.Get(s, "status-version", "2"),
		o.Get(s, "auth", "SHA512"),
		o.Get(s, "reneg-sec", "3600"),
		o.Get(s, "machine-readable-output", ""),
		o.Get(s, "tun-mtu", "1500"),
	}...)
	if s.Network.Crosstalk {
		d = append(d, o.Get(s, "client-to-client", ""))
	}
	if s.Service.Protocol == UDP {
		d = append(d, []string{
			o.Get(s, "explicit-exit-notify", "1"),
			o.Get(s, "connect-freq", "1 sec"),
			o.Get(s, "fast-io", ""),
		}...)
	}
	d = append(d, []string{
		o.Get(
			s, "keepalive",
			strconv.FormatUint(uint64(s.Config.Limits.KeepAlive.Interval), 10)+" "+strconv.FormatUint(uint64(s.Config.Limits.KeepAlive.Timeout), 10),
		),
		o.Get(s, "max-clients", strconv.FormatUint(uint64(s.Config.Limits.Max), 10)),
		o.Get(s, "user", "nobody"),
		o.Get(s, "group", "nobody"),
		o.Get(s, "persist-key", ""),
		o.Get(s, "persist-tun", ""),
		o.Get(s, "allow-compression", "no"),
		o.Get(s, "remote-cert-tls", "client"),
		o.Get(s, "cipher", "AES-256-GCM"),
		o.Get(s, "data-ciphers", "AES-256-GCM:AES-256-CBC:CAMELLIA-256-CBC:AES-128-GCM"),
		o.Get(s, "tls-server", ""),
		o.Get(s, "tls-version-min", "1.2"),
		o.Get(s, "tls-ciphersuites", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"),
		o.Get(
			s, "tls-cipher", "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256",
		),
		o.Get(s, "tls-groups", "X25519:secp256r1:X448:secp521r1:secp384r1"),
		o.Get(s, "key-direction", "0"),
	}...)
	for i := range d {
		if len(d[i]) == 0 {
			continue
		}
		if _, err = f.WriteString(d[i] + "\n"); err != nil {
			break
		}
	}
	if err != nil {
		f.Close()
		return xerr.Wrap(`cannot write to "`+p+`"`, err)
	}
	if len(s.Service.Auth.File) > 0 {
		_, err = f.WriteString("tls-crypt-v2 " + s.Service.Auth.File + "\n")
	} else if len(s.Service.Auth.Data) > 0 {
		if _, err = f.WriteString("<tls-crypt-v2>\n"); err == nil {
			if _, err = f.Write(s.Service.Auth.Data); err == nil {
				_, err = f.WriteString("\n</tls-crypt-v2>\n")
			}
		}
	}
	if err != nil {
		f.Close()
		return xerr.Wrap(`cannot write to "`+p+`"`, err)
	}
	for _, x := range s.Config.Options {
		if !x.Client {
			if _, err = f.WriteString(x.Value + "\n"); err != nil {
				break
			}
		}
		if x.Push {
			if _, err = f.WriteString(`push "` + x.Value + "\"\n"); err != nil {
				break
			}
		}
	}
	err2 := f.Close()
	if os.Chmod(p, 0400); err != nil {
		return err
	}
	return err2
}

// NewClient will generate the client key material based on the server TLS data and will return the VPN profile
// as a byte array
func (s *Server) NewClient(name, email string, days int) ([]byte, *pki.Certificate, []byte, error) {
	if atomic.LoadUint32(&s.active) == 2 {
		return nil, nil, nil, errBlocked
	}
	var x context.Context
	x, s.cancel = context.WithCancel(context.Background())
	if b, err := s.prep(x, false); b && err == nil {
		s.log.Error("[server/new-client] %s: Server is blocked on an operation, cannot create a new client currently!", s.ID)
		return nil, nil, nil, xerr.New(`server "` + s.ID + `" is blocked on an operation, please wait`)
	} else if s.cancel(); err != nil {
		return nil, nil, nil, err
	}
	s.log.Info("[server/newclient] %s: Attempting to create a client certificate for %q...", s.ID, name)
	k := s.Service.Auth.File
	if len(k) == 0 {
		f, err := ioutil.TempFile("", s.ID+"-server-*.key")
		if err != nil {
			return nil, nil, nil, xerr.Wrap("could not create temp file for key", err)
		}
		s.log.Debug("[server/newclient] %s: Writing inline key to disk as %q...", s.ID, f.Name())
		if _, err = f.Write(s.Service.Auth.Data); err != nil {
			return nil, nil, nil, xerr.Wrap("could not write key file", err)
		}
		if err := f.Close(); err != nil {
			return nil, nil, nil, xerr.Wrap("could not close key file", err)
		}
		k = f.Name()
	}
	o, err := exec.Command("openvpn", "--tls-crypt-v2", k, "--genkey", "tls-crypt-v2-client").Output()
	if len(s.Service.Auth.File) == 0 {
		if err := os.Remove(k); err != nil {
			s.log.Warning("[server/newclient] %s: Error attempting to remove temp file %q: %s!", s.ID, k, err.Error())
		}
	}
	if err != nil {
		return nil, nil, nil, xerr.Wrap("could not generate client secret", err)
	}
	if len(o) > 0 && o[len(o)-1] == 10 {
		o = o[:len(o)-1]
	}
	c, err := s.CA.CreateClient(name, email, days)
	if err != nil {
		return nil, nil, nil, xerr.Wrap("could not generate client certificate", err)
	}
	p, err := s.profile(c, o)
	if err != nil {
		c.Revoke()
		return nil, nil, nil, xerr.Wrap("could not generate client profile", err)
	}
	s.actionCreate(parseName(name), email)
	return p, c, o, nil
}
