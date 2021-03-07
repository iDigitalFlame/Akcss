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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/iDigitalFlame/akcss/xerr"
)

const (
	socket    = "/var/run/ackss.sock"
	socketTCP = "127.0.0.1:9090"
)

var (
	errNoEnv      = xerr.New("inline environment is missing")
	errNoName     = xerr.New("required client name is missing")
	errNoValue    = xerr.New("required option value is missing")
	errNoEmail    = xerr.New("required email address is missing")
	errAborted    = xerr.New("operation aborted")
	errValidID    = xerr.New("server ID is invalid")
	errUnexpected = xerr.New("unexpected server response")
)

// Start is the primary command line function start point for Akcss, which will parse the flags and create
// the Akcss instance.
func Start() {
	if f := new(flags).setup(); f.valid() {
		if err := f.exec(); err != nil {
			os.Stderr.WriteString(err.Error() + "!\n")
			os.Exit(1)
		}
	} else {
		os.Stderr.WriteString(usage)
		os.Exit(2)
	}
}
func (f flags) exec() error {
	if f.Command.Daemon {
		return daemon(f.Args.Config)
	}
	if f.Command.Inline && (f.details.Service.Hostname.V == "c" || f.details.Service.Hostname.V == "d") {
		if f.sock = socket; len(f.Extra) >= 1 && len(f.Extra[0]) > 0 {
			f.sock = f.Extra[0]
		}
		var (
			n, ok  = os.LookupEnv("common_name")
			r, ok1 = os.LookupEnv("untrusted_ip")
			l, ok2 = os.LookupEnv("ifconfig_pool_remote_ip")
			d, ok3 = os.LookupEnv("time_duration")
		)
		if f.details.Service.Hostname.V == "c" {
			if !ok || !ok1 || !ok2 {
				return errNoEnv
			}
			return f.sendOk(actionConnect, responseOk, "", typeConnect{ID: f.ID, Name: n, Local: l, Remote: r})
		}
		if !ok || !ok1 || !ok3 {
			return errNoEnv
		}
		i, err := strconv.ParseUint(d, 10, 64)
		if err != nil {
			return xerr.Wrap(`cannot parse duration "`+d+`"`, err)
		}
		return f.sendOk(actionDisconnect, responseOk, "", typeConnect{
			ID: f.ID, Name: n, Local: l, Duration: time.Duration(i) * time.Second,
		})
	}
	b, err := ioutil.ReadFile(f.Args.Config)
	if err != nil {
		return xerr.Wrap(`unable to read "`+f.Args.Config+`"`, err)
	}
	var m map[string]json.RawMessage
	if err = json.Unmarshal(b, &m); err != nil {
		return xerr.Wrap(`unable to parse "`+f.Args.Config+`"`, err)
	}
	if v, ok := m["sock"]; ok {
		if err = json.Unmarshal(v, &f.sock); err != nil {
			return xerr.Wrap(`unable to parse "`+f.Args.Config+`"`, err)
		}
		if len(f.sock) == 0 {
			f.sock = socket
		}
	}
	if f.Command.List && len(f.ID) == 0 {
		r, err := f.send(actionServerList, responseServerList, "", nil)
		if err != nil {
			return err
		}
		v, ok := r.e.(*typeServerList)
		if !ok {
			return errUnexpected
		}
		os.Stdout.WriteString("ID      Auto Run PID     Port        Hostname\n==================================================\n")
		for _, x := range v.Servers {
			os.Stdout.WriteString(exp(x.ID, 8))
			if x.Auto {
				os.Stdout.WriteString(" X   ")
			} else {
				os.Stdout.WriteString("     ")
			}
			if x.Running {
				os.Stdout.WriteString(" X  ")
			} else {
				os.Stdout.WriteString("    ")
			}
			os.Stdout.WriteString(
				exp(strconv.FormatUint(x.PID, 10), 8) + exp(strconv.FormatUint(uint64(x.Port), 10)+"/"+
					x.Protocol, 10) + " " + x.Hostname + "\n",
			)
		}
		return nil
	}
	if f.Command.Reload && len(f.ID) == 0 {
		return f.sendOk(actionReload, responseOk, "", nil)
	}
	if f.Command.CRL {
		if len(f.ID) > 0 && !valid(f.ID) {
			return xerr.Wrap(f.ID, errValidID)
		}
		return f.sendOk(actionCRL, responseOk, f.ID, nil)
	}
	if !valid(f.ID) {
		if len(f.ID) == 0 {
			return errInvalidID
		}
		return xerr.Wrap(f.ID, errValidID)
	}
	return f.command()
}
func (f flags) action() error {
	switch {
	case f.Command.Server.New:
		if err := f.verify(true); err != nil {
			return err
		}
		return f.sendOk(actionServerNew, responseOk, "", f.details)
	case f.Command.Server.Edit:
		if err := f.verify(false); err != nil {
			return err
		}
		return f.sendOk(actionUpdate, responseOk, "", f.details)
	case f.Command.Server.Delete:
		if !f.Args.Force {
			if !confirm(`Are you sure you want to delete the server "`+f.ID+`"? [y/N]`, false) {
				return errAborted
			}
		}
		return f.sendOk(actionServerDelete, responseOk, "", typeServerDelete{ID: f.ID, Soft: f.Args.Soft})
	case f.Command.Client.New:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoName
		}
		l := f.Subject.Days.Client.V
		if f.Subject.Days.Server.S {
			l = f.Subject.Days.Server.V
		}
		r, err := f.send(actionClientNew, responseClientNew, "", typeClientNew{
			ID: f.ID, Name: f.Service.Hostname.V, Days: l, Email: f.Subject.Email.V,
		})
		if err != nil {
			return err
		}
		if len(f.Args.Output) == 0 {
			os.Stdout.Write(r.Data)
			os.Stdout.WriteString("\n")
			return nil
		}
		return ioutil.WriteFile(f.Args.Output, r.Data, 0600)
	case f.Command.Client.Delete:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoName
		}
		if !f.Args.Force {
			if !confirm(`Are you sure you want to delete the client "`+f.Service.Hostname.V+`" on server "`+f.ID+`"? [y/N]`, false) {
				return errAborted
			}
		}
		return f.sendOk(actionClientDelete, responseOk, "", typeClientDelete{ID: f.ID, Name: f.Service.Hostname.V})
	case f.Command.Option.New:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoValue
		}
		return f.sendOk(actionOptionNew, responseOk, "", typeOption{
			ID: f.ID, Value: f.Service.Hostname.V, Push: f.Args.Option.Push, Config: f.Args.Option.Config,
		})
	case f.Command.Option.List:
		r, err := f.send(actionOptionList, responseOptionList, f.ID, nil)
		if err != nil {
			return err
		}
		if v, ok := r.e.(*typeOptionList); ok {
			os.Stdout.WriteString("Pushed  Client  Value\n=============================================\n")
			for _, x := range v.Options {
				if x.Push {
					os.Stdout.WriteString("     y  ")
				} else {
					os.Stdout.WriteString("     n  ")
				}
				if x.Config {
					os.Stdout.WriteString("     y  ")
				} else {
					os.Stdout.WriteString("     n  ")
				}
				os.Stdout.WriteString(x.Value + "\n")
			}
			return nil
		}
		return errUnexpected
	case f.Command.Option.Delete:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoValue
		}
		return f.sendOk(actionOptionDelete, responseOk, "", typeOption{
			ID: f.ID, Value: f.Service.Hostname.V, Push: f.Args.Option.Push, Config: f.Args.Option.Config,
		})
	case f.Command.Option.Client.New:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoName
		}
		if len(f.Extra) == 0 {
			return errNoValue
		}
		return f.sendOk(actionOptionClientNew, responseOk, "", typeOption{
			ID: f.ID, Client: f.Service.Hostname.V, Value: strings.Join(f.Extra, " "),
		})
	case f.Command.Option.Client.List:
		r, err := f.send(actionOptionClientList, responseOptionClientList, f.ID, nil)
		if err != nil {
			return err
		}
		if v, ok := r.e.(*typeOptionList); ok {
			os.Stdout.WriteString("Client                        Value\n=============================================\n")
			for _, x := range v.Options {
				os.Stdout.WriteString(exp(x.Client, 30) + x.Value + "\n")
			}
			return nil
		}
		return errUnexpected
	case f.Command.Option.Client.Delete:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoName
		}
		if len(f.Extra) == 0 {
			return errNoValue
		}
		return f.sendOk(actionOptionClientDelete, responseOk, "", typeOption{
			ID: f.ID, Client: f.Service.Hostname.V, Value: strings.Join(f.Extra, " "),
		})
	case f.Command.Notify.New:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoEmail
		}
		if err := f.sendOk(
			actionNotifyNew, responseOk, "", typeNotify{ID: f.ID, Email: f.Service.Hostname.V, Action: f.Args.Actions},
		); err != nil {
			return err
		}
		for _, x := range f.Extra {
			if len(x) == 0 {
				continue
			}
			if err := f.sendOk(actionNotifyNew, responseOk, "", typeNotify{ID: f.ID, Email: x, Action: f.Args.Actions}); err != nil {
				return err
			}
		}
		return nil
	case f.Command.Notify.List:
		r, err := f.send(actionNotifyList, responseNotifyList, f.ID, nil)
		if err != nil {
			return err
		}
		if v, ok := r.e.(*typeNotifyList); ok {
			os.Stdout.WriteString("Email                    Actions\n=============================================\n")
			for _, x := range v.Notifiers {
				os.Stdout.WriteString(exp(x.Email, 25) + x.Action + "\n")
			}
			return nil
		}
		return errUnexpected
	case f.Command.Notify.Delete:
		if !f.Service.Hostname.S || len(f.Service.Hostname.V) == 0 {
			return errNoEmail
		}
		if err := f.sendOk(actionNotifyDelete, responseOk, "", typeNotify{ID: f.ID, Email: f.Service.Hostname.V}); err != nil {
			return err
		}
		for _, x := range f.Extra {
			if len(x) == 0 {
				continue
			}
			if err := f.sendOk(actionNotifyDelete, responseOk, "", typeNotify{ID: f.ID, Email: x}); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}
func (f flags) command() error {
	switch {
	case f.Command.List:
		r, err := f.send(actionClientList, responseClientList, f.ID, nil)
		if err != nil {
			return err
		}
		if v, ok := r.e.(*typeClientList); ok {
			os.Stdout.WriteString("Name\n=============================================\n")
			for _, x := range v.Clients {
				os.Stdout.WriteString(x + " \n")
			}
			return nil
		}
		return errUnexpected
	case f.Command.Stop:
		return f.sendOk(actionStop, responseOk, f.ID, nil)
	case f.Command.Show:
		r, err := f.send(actionShow, responseShow, f.ID, nil)
		if err != nil {
			return err
		}
		if v, ok := r.e.(*typeServer); ok {
			v.Print(os.Stdout)
			return nil
		}
		return errUnexpected
	case f.Command.Start:
		r, err := f.send(actionStart, responseStatus, f.ID, nil)
		if err != nil {
			return err
		}
		if v, ok := r.e.(*typeStatus); ok {
			if v.PID == 0 {
				os.Stdout.WriteString("Server will start after DHParam generation is complete!\n")
				return nil
			}
			os.Stdout.WriteString("Server process PID: " + strconv.FormatUint(v.PID, 10) + " started!\n")
			return nil
		}
		return errUnexpected
	case f.Command.Renew:
		return f.sendOk(actionRenew, responseOk, f.ID, nil)
	case f.Command.Status:
		r, err := f.send(actionStatus, responseStatus, f.ID, nil)
		if err != nil {
			return err
		}
		if v, ok := r.e.(*typeStatus); ok {
			os.Stdout.WriteString(
				"Server " + f.ID + " PID: " + strconv.FormatUint(v.PID, 10) +
					"\n\nName           Local          Remote         Connect\n" +
					"==================================================================\n",
			)
			for _, x := range v.Status {
				os.Stdout.WriteString(
					exp(x.Name, 15) + exp(x.Local, 15) + exp(x.Remote, 15) + x.Start.Format(time.Stamp) + "\n",
				)
			}
			return nil
		}
		return errUnexpected
	case f.Command.Restart && !f.Command.Server.Edit && !f.Command.Server.New:
		return f.sendOk(actionRestart, responseOk, f.ID, nil)
	}
	return f.action()
}
func (f flags) sendOk(a, e uint8, p string, d interface{}) error {
	_, err := f.send(a, e, p, d)
	return err
}
func (f flags) send(a, e uint8, p string, d interface{}) (*message, error) {
	m := message{Action: a, e: d}
	if len(p) > 0 {
		m.Data = []byte(p)
	}
	if len(f.sock) == 0 {
		f.sock = socket
	}
	r, err := write(context.Background(), f.sock, m)
	if err != nil {
		return nil, err
	}
	if r.Action == responseError {
		return nil, xerr.New(string(r.Data))
	}
	if r.Action != e {
		return nil, xerr.New(`unexpected response "` + r.String() + `"`)
	}
	if err = r.Parse(); err != nil {
		return nil, err
	}
	return r, nil
}
