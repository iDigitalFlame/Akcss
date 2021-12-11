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

package akcss

import (
	"flag"
	"os"
	"strconv"
	"strings"

	"github.com/iDigitalFlame/akcss/xerr"
)

const maxUint16 uint64 = 2 << 15

var (
	errNotZero  = xerr.New("cannot be zero")
	errNotEmpty = xerr.New("cannot be empty")
)

type flags struct {
	*flag.FlagSet
	sock string

	Args struct {
		File struct {
			DH   string
			Auth string
		}
		Actions string
		Output  string
		Config  string
		Option  struct {
			Push   bool
			Config bool
		}
		Force bool
		Fault bool
		Soft  bool
	}
	Extra []string
	details

	Command struct {
		CRL    bool
		List   bool
		Show   bool
		Stop   bool
		Start  bool
		Renew  bool
		Config bool
		Status bool
		Daemon bool
		Reload bool
		Inline bool
		Server struct {
			New    bool
			Edit   bool
			Delete bool
		}
		Client struct {
			New    bool
			List   bool
			Delete bool
		}
		Option struct {
			New    bool
			List   bool
			Delete bool
			Client struct {
				New    bool
				List   bool
				Delete bool
			}
		}
		Notify struct {
			New    bool
			List   bool
			Delete bool
		}
		Restart bool
	}
}
type details struct {
	ID      string `json:"id"`
	Network struct {
		Range struct {
			End   flagString `json:"end,omitempty"`
			Mask  flagString `json:"mask,omitempty"`
			Base  flagString `json:"base,omitempty"`
			Start flagString `json:"start,omitempty"`
		} `json:"range"`
		Crosstalk flagBool `json:"cross,omitempty"`
	} `json:"network"`
	DH struct {
		File  flagString `json:"file,omitempty"`
		Data  []byte     `json:"data,omitempty"`
		Size  flagUint16 `json:"size,omitempty"`
		Empty bool       `json:"empty,omitempty"`
	} `json:"dh"`
	Subject struct {
		CA           flagString `json:"ca,omitempty"`
		ZIP          flagString `json:"zip,omitempty"`
		City         flagString `json:"city,omitempty"`
		Department   flagString `json:"dept,omitempty"`
		State        flagString `json:"state,omitempty"`
		Email        flagString `json:"email,omitempty"`
		Street       flagString `json:"street,omitempty"`
		Domain       flagString `json:"domain,omitempty"`
		Country      flagString `json:"country,omitempty"`
		Organization flagString `json:"org,omitempty"`
		Days         struct {
			CA     flagUint16 `json:"ca,omitempty"`
			Client flagUint16 `json:"client,omitempty"`
			Server flagUint16 `json:"server,omitempty"`
		}
	} `json:"subject"`
	Service struct {
		Protocol flagString `json:"proto,omitempty"`
		Hostname flagString `json:"hostname,omitempty"`
		Auth     struct {
			File  flagString `json:"file,omitempty"`
			Data  []byte     `json:"data,omitempty"`
			Empty bool       `json:"empty,omitempty"`
		} `json:"auth"`
		Port flagUint16 `json:"port,omitempty"`
	} `json:"server"`
	Config struct {
		Override struct {
			Client flagString `json:"client,omitempty"`
			Server flagString `json:"server,omitempty"`
		}
		Limits struct {
			Max       flagUint16 `json:"max,omitempty"`
			KeepAlive struct {
				Timeout  flagUint16 `json:"timeout,omitempty"`
				Interval flagUint16 `json:"interval,omitempty"`
			} `json:"keep_alive"`
		} `json:"limits"`
		Auto flagBool `json:"auto,omitempty"`
	} `json:"config"`
	Restart bool `json:"now,omitempty"`
}
type flagBool struct {
	S bool `json:"set,omitempty"`
	V bool `json:"val,omitempty"`
}
type flagString struct {
	V string `json:"val,omitempty"`
	S bool   `json:"set,omitempty"`
}
type flagUint16 struct {
	S bool   `json:"set,omitempty"`
	V uint16 `json:"val,omitempty"`
}
type boolean interface {
	IsBoolFlag() bool
}
type flagBooleans []*bool

func (f *flags) parse() {
	if err := f.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Stderr.WriteString(usage)
			os.Exit(2)
		}
		os.Exit(1)
	}
	for i, a := 0, f.FlagSet.Args(); i < len(a); i++ {
		if len(a[i]) <= 1 || a[i][0] != '-' || i+1 > len(a) {
			f.Extra = append(f.Extra, a[i])
			continue
		}
		var x *flag.Flag
		if a[i][1] == '-' {
			x = f.Lookup(a[i][2:])
		} else {
			x = f.Lookup(a[i][1:])
		}
		if x == nil {
			if a[i][1] == '-' {
				if p := strings.IndexByte(a[i], '='); p > 2 && p < len(a[i])-2 {
					if x = f.Lookup(a[i][2:p]); x != nil {
						if err := x.Value.Set(a[i][p+1:]); err != nil {
							os.Stderr.WriteString(`invalid value "` + a[i][p+1:] + `" for flag "--` + x.Name + `": ` + err.Error() + "\n")
							os.Exit(1)
						}
						continue
					}
				}
			}
			f.Extra = append(f.Extra, a[i])
			continue
		}
		if b, ok := x.Value.(boolean); ok && b.IsBoolFlag() {
			x.Value.Set("true")
			continue
		}
		if i+1 >= len(a) {
			break
		}
		if err := x.Value.Set(a[i+1]); err != nil {
			os.Stderr.WriteString(`invalid value "` + a[i+1] + `" for flag "--` + x.Name + `": ` + err.Error() + "\n")
			os.Exit(1)
		}
		i++
	}
	if len(f.Extra) == 1 {
		f.ID, f.Extra = f.Extra[0], nil
	} else if len(f.Extra) >= 2 {
		if f.Service.Hostname.S {
			f.ID, f.Extra = f.Extra[0], f.Extra[1:]
		} else {
			f.Service.Hostname.Set(f.Extra[1])
			f.ID, f.Extra = f.Extra[0], f.Extra[2:]
		}
	}
	if v, ok := os.LookupEnv("AKCSS_CONF"); ok {
		f.Args.Config = v
	}
	if len(f.Args.Config) == 0 {
		f.Args.Config = "/etc/akcss.conf"
	}
}
func (f *flags) valid() bool {
	return f.Command.CRL || f.Command.List || f.Command.Stop || f.Command.Start || f.Command.Renew || f.Command.Show ||
		f.Command.Status || f.Command.Daemon || f.Command.Inline || f.Command.Reload || f.Command.Restart ||
		f.Command.Server.New || f.Command.Server.Edit || f.Command.Server.Delete ||
		f.Command.Option.New || f.Command.Option.List || f.Command.Option.Delete ||
		f.Command.Option.Client.New || f.Command.Option.Client.List || f.Command.Option.Client.Delete ||
		f.Command.Client.New || f.Command.Client.Delete ||
		f.Command.Notify.New || f.Command.Notify.List || f.Command.Notify.Delete || f.Command.Config
}
func (f *flags) setup() *flags {
	f.FlagSet = flag.NewFlagSet("Akcss - OpenVPN Manager", flag.ContinueOnError)
	f.FlagSet.Usage = func() {}

	// General
	f.StringVar(&f.Args.Config, "c", "", "")
	f.BoolVar(&f.Command.Reload, "r", false, "")
	f.BoolVar(&f.Command.Daemon, "daemon", false, "")
	f.BoolVar(&f.Command.Config, "d", false, "")
	f.BoolVar(&f.Args.Fault, "no-fault", false, "")

	// Boolean Multi Pointers
	var s, r = flagBooleans{&f.Command.Start, &f.Restart}, flagBooleans{&f.Command.Restart, &f.Restart}

	// Server Commands
	f.BoolVar(&f.Command.List, "list", false, "")
	f.BoolVar(&f.Command.Stop, "stop", false, "")
	f.Var(s, "start", "")
	f.BoolVar(&f.Command.Renew, "renew", false, "")
	f.BoolVar(&f.Command.Status, "status", false, "")
	f.Var(r, "restart", "")
	f.BoolVar(&f.Command.CRL, "crl", false, "")
	f.BoolVar(&f.Command.Show, "print", false, "")
	f.BoolVar(&f.Command.Inline, "il", false, "")

	// Server Actions
	f.BoolVar(&f.Command.Server.New, "new", false, "")
	f.BoolVar(&f.Command.Server.Edit, "edit", false, "")
	f.BoolVar(&f.Command.Server.Delete, "delete", false, "")

	// Server Options (for --new and --edit)
	f.Var(&f.Service.Hostname, "hostname", "")
	f.Var(&f.Service.Port, "port", "")
	f.Var(&f.Service.Protocol, "proto", "")
	f.Var(&f.Config.Auto, "auto", "")
	f.Var(&f.Config.Limits.Max, "limit", "")
	f.Var(&f.Config.Limits.KeepAlive.Timeout, "timeout", "")
	f.Var(&f.Config.Limits.KeepAlive.Interval, "interval", "")
	f.Var(&f.Subject.Days.Server, "days", "")
	f.Var(&f.Subject.Days.Client, "client-days", "")
	f.Var(&f.Subject.Days.Server, "server-days", "")
	f.Var(&f.Config.Override.Client, "over-client", "")
	f.Var(&f.Config.Override.Server, "over-server", "")

	// VPN Network Options
	f.Var(&f.Network.Crosstalk, "crosstalk", "")
	f.Var(&f.Network.Range.Base, "net", "")
	f.Var(&f.Network.Range.Start, "net-start", "")
	f.Var(&f.Network.Range.End, "net-end", "")
	f.Var(&f.Network.Range.Mask, "net-mask", "")

	// CA Options (only valid for --new)
	f.Var(&f.Subject.CA, "ca", "")
	f.Var(&f.Subject.Days.CA, "ca-days", "")

	// Certificate Subject Options
	f.Var(&f.Subject.Organization, "org", "")
	f.Var(&f.Subject.Department, "dept", "")
	f.Var(&f.Subject.Street, "street", "")
	f.Var(&f.Subject.City, "city", "")
	f.Var(&f.Subject.State, "state", "")
	f.Var(&f.Subject.Country, "country", "")
	f.Var(&f.Subject.Domain, "domain", "")
	f.Var(&f.Subject.Email, "email", "")

	// DH Options
	f.Var(&f.DH.File, "dh-path", "")
	f.StringVar(&f.Args.File.DH, "dh-file", "", "")
	f.Var(&f.DH.Size, "dh-size", "")
	f.BoolVar(&f.DH.Empty, "no-dh", false, "")

	// TLS Secrets Options
	f.Var(&f.Service.Auth.File, "tls-path", "")
	f.StringVar(&f.Args.File.Auth, "tls-file", "", "")
	f.BoolVar(&f.Service.Auth.Empty, "tls-gen", false, "")
	f.BoolVar(&f.Service.Auth.Empty, "tls-reset", false, "")

	// Server Options (for --delete)
	f.BoolVar(&f.Args.Force, "force", false, "")
	f.BoolVar(&f.Args.Soft, "soft", false, "")

	// OpenVPN Option Actions
	f.BoolVar(&f.Command.Option.List, "opt", false, "")
	f.BoolVar(&f.Command.Option.New, "new-opt", false, "")
	f.BoolVar(&f.Command.Option.Delete, "del-opt", false, "")

	//Additional Options (for --new-opt)
	f.BoolVar(&f.Args.Option.Push, "push", false, "")
	f.BoolVar(&f.Args.Option.Config, "push-client", false, "")

	// OpenVPN Client Option Commands
	f.BoolVar(&f.Command.Option.Client.List, "cc", false, "")
	f.BoolVar(&f.Command.Option.Client.New, "new-cc", false, "")
	f.BoolVar(&f.Command.Option.Client.Delete, "del-cc", false, "")

	// Client Actions
	f.BoolVar(&f.Command.Client.New, "new-client", false, "")
	f.BoolVar(&f.Command.Client.Delete, "del-client", false, "")

	// Additional Options (for --new-client)
	f.StringVar(&f.Args.Output, "file", "", "")

	// Notification Actions
	f.BoolVar(&f.Command.Notify.List, "notify", false, "")
	f.BoolVar(&f.Command.Notify.New, "new-notify", false, "")
	f.BoolVar(&f.Command.Notify.Delete, "del-notify", false, "")

	// Additional Options (for --new-notify)
	f.StringVar(&f.Args.Actions, "actions", "", "")

	f.parse()
	return f
}
func (f flagBool) String() string {
	if f.V {
		return "true"
	}
	return "false"
}
func (flagBool) IsBoolFlag() bool {
	return true
}
func (f flagString) String() string {
	return f.V
}
func (f flagUint16) String() string {
	return strconv.FormatUint(uint64(f.V), 10)
}
func (f *flags) verify(n bool) error {
	var err error
	if len(f.Args.File.DH) > 0 {
		if f.DH.Data, err = os.ReadFile(f.Args.File.DH); err != nil {
			return err
		}
	}
	if len(f.Args.File.Auth) > 0 {
		if f.Service.Auth.Data, err = os.ReadFile(f.Args.File.Auth); err != nil {
			return err
		}
	}
	return f.details.verify(n)
}
func (d details) verify(n bool) error {
	if !valid(d.ID) {
		return errInvalidID
	}
	if d.DH.Size.S {
		switch d.DH.Size.V {
		case 0, 2048, 4096:
		default:
			return xerr.New(`dhparam size "` + strconv.FormatUint(uint64(d.DH.Size.V), 10) + `" is not valid (must be: 0, 2048 or 4096)`)
		}
	}
	if d.DH.File.S && len(d.DH.File.V) > 0 {
		if _, err := os.Stat(d.DH.File.V); err != nil {
			return xerr.Wrap(`dhparam path "`+d.DH.File.V+`" is not valid`, err)
		}
	}
	if d.Config.Limits.Max.S && d.Config.Limits.Max.V == 0 {
		return xerr.Wrap("client limit", errNotZero)
	}
	if d.Config.Limits.KeepAlive.Timeout.S && d.Config.Limits.KeepAlive.Timeout.V == 0 {
		return xerr.Wrap("keepalive timeout", errNotZero)
	}
	if d.Config.Limits.KeepAlive.Interval.S && d.Config.Limits.KeepAlive.Interval.V == 0 {
		return xerr.Wrap("keepalive interval", errNotZero)
	}
	if d.Network.Range.Base.S && len(d.Network.Range.Base.V) == 0 {
		return xerr.Wrap("network", errNotEmpty)
	}
	if d.Network.Range.Mask.S && len(d.Network.Range.Mask.V) == 0 {
		return xerr.Wrap("network mask", errNotEmpty)
	}
	if d.Service.Auth.File.S && len(d.Service.Auth.File.V) > 0 {
		if _, err := os.Stat(d.Service.Auth.File.V); err != nil {
			return xerr.Wrap(`tls auth path "`+d.Service.Auth.File.V+`" is not valid`, err)
		}
	}
	if d.Service.Port.S && d.Service.Port.V == 0 {
		return xerr.Wrap("port", errNotZero)
	}
	if d.Service.Protocol.S {
		switch strings.ToLower(d.Service.Protocol.V) {
		case "tcp", "t", "udp", "u":
		default:
			return xerr.New(`protocol "` + d.Service.Protocol.V + `" is not valid`)
		}
	}
	if d.Service.Hostname.S && len(d.Service.Hostname.V) == 0 {
		return xerr.Wrap("hostname", errNotEmpty)
	}
	if d.Subject.CA.S && len(d.Subject.CA.V) == 0 {
		return xerr.Wrap("subject CA", errNotEmpty)
	}
	if d.Subject.Country.S && len(d.Subject.Country.V) != 2 {
		return errInvalidCountry
	}
	if d.Subject.Organization.S && len(d.Subject.Organization.V) == 0 {
		return xerr.Wrap("subject organization", errNotEmpty)
	}
	if n {
		if !d.Subject.Country.S {
			return errInvalidCountry
		}
		if !d.Subject.Organization.S {
			return xerr.Wrap("subject organization", errNotEmpty)
		}
	}
	return nil
}
func (f flagBooleans) String() string {
	return "false"
}
func (flagBooleans) IsBoolFlag() bool {
	return true
}
func (f *flagBool) Set(v string) error {
	if f.S = true; len(v) == 0 {
		return nil
	}
	switch strings.ToLower(v) {
	case "1", "t", "y", "yes", "true":
		f.V = true
	}
	return nil
}
func (f *flagString) Set(v string) error {
	f.S, f.V = true, v
	return nil
}
func (f *flagUint16) Set(v string) error {
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		if e, ok := err.(*strconv.NumError); ok {
			switch e.Err {
			case strconv.ErrRange:
				return xerr.New(`number "` + v + `" cannot be larger than "65535"`)
			case strconv.ErrSyntax:
				return xerr.New(`number "` + v + `" is invalid`)
			}
		}
		return err
	}
	if n > maxUint16 {
		return xerr.New(`number "` + v + `" cannot be larger than "65535"`)
	}
	f.S, f.V = true, uint16(n)
	return nil
}
func (f flagBooleans) Set(v string) error {
	if len(v) == 0 {
		return nil
	}
	switch strings.ToLower(v) {
	case "1", "t", "y", "yes", "true":
		for i := range f {
			*f[i] = true
		}
	}
	return nil
}
