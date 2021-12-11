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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/iDigitalFlame/akcss/xerr"
)

const (
	format = "01/02/2006 15:04:05"

	actionCRL action = 1 << iota
	actionStop
	actionStart
	actionRenew
	actionCreate
	actionExpire
	actionRevoke
	actionConnect
	actionDisconnect
	actionAll action = 0xFFFF

	msgCRLBody = `Hello,

This is a notification that server %q (%s) has regenerated it's CRL list on %s.%s

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgNewBody = `Hello,

A new VPN profile %q was generated for the server %q on %s. This client now has access to the VPN service hosted on %q.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgStopBody = `Hello,

The server %q (%s) was stopped on %s.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgStartBody = `Hello,

The server %q (%s) was started on %s.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgRenewBody = `Hello,

The server %q (%s) has renewed it's hosting certificate on %s.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgNewOwnBody = `Hello,

There is a new VPN profile %q generated for you to connect to the VPN service %q.

Please contact the VPN Administrator to receive the profile and any usage instructions.

 - Akcss VPN Service.
`
	msgExpireBody = `Hello,

The profile %q for server %q (%s) has expired on %s. Please ensure that the profile holder has been notified to prevent VPN access interruptions.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgRevokeBody = `Hello,

The profile %q for server %q (%s) was revoked on %s. The user with this profile can no longer access the VPN on %q.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgConnectBody = `Hello,

The profile %q connected to %q (%s) on %s.
The connected device was assigned the internal network address %q linked to the external address %q.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
	msgDisconnectBody = `Hello,

The profile %q disconnected from %q (%s) on %s.
The device was assigned the internal network address %q and was active for %s.

You are receiving this email as you were subscribed for notifications by the VPN Administrator.

 - Akcss VPN Service
`
)

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return " on " + h
}
func (s *Server) actionStop() {
	s.notify(
		actionStop, `Akcss: VPN `+s.ID+` was Stopped`,
		fmt.Sprintf(msgStopBody, s.ID, s.Service.Hostname, time.Now().Format(format))+hostname(),
	)
}
func (s *Server) actionStart() {
	s.notify(
		actionStart, `Akcss: VPN `+s.ID+` was Started`,
		fmt.Sprintf(msgStartBody, s.ID, s.Service.Hostname, time.Now().Format(format))+hostname(),
	)
}
func (s *Server) actionRenew() {
	s.notify(
		actionRenew, `Akcss: VPN `+s.ID+` has Renewed it's Server Certificate`,
		fmt.Sprintf(msgRenewBody, s.ID, s.Service.Hostname, time.Now().Format(format))+hostname(),
	)
}
func (a action) String() string {
	if a == actionAll {
		return "all"
	}
	var b strings.Builder
	if a&actionCRL != 0 {
		b.WriteString("crl")
	}
	if a&actionStop != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("stop")
	}
	if a&actionStart != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("start")
	}
	if a&actionRenew != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("renew")
	}
	if a&actionExpire != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("expire")
	}
	if a&actionCreate != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("create")
	}
	if a&actionRevoke != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("revoke")
	}
	if a&actionConnect != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("connect")
	}
	if a&actionDisconnect != 0 {
		if b.Len() > 0 {
			b.WriteRune(',')
		}
		b.WriteString("disconnect")
	}
	s := b.String()
	b.Reset()
	return s
}
func (s *Server) actionCRL(l string) {
	s.notify(
		actionCRL, `Akcss: VPN `+s.ID+` CRL was Updated`,
		fmt.Sprintf(msgCRLBody, s.ID, s.Service.Hostname, time.Now().Format(format), l)+hostname(),
	)
}
func parse(s string) (action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "all", "*":
		return actionAll, nil
	case "new":
		return actionCreate, nil
	case "crl":
		return actionCRL, nil
	case "stop":
		return actionStop, nil
	case "start":
		return actionStart, nil
	case "renew":
		return actionRenew, nil
	case "expire":
		return actionExpire, nil
	case "create":
		return actionCreate, nil
	case "revoke":
		return actionRevoke, nil
	case "connect":
		return actionConnect, nil
	case "disconnect":
		return actionDisconnect, nil
	default:
		return 0, xerr.New(`invalid event name "` + s + `"`)
	}
}
func (s *Server) actionExpire(n string) {
	s.notify(
		actionExpire, `Akcss: VPN `+s.ID+` Profile "`+n+`" has Expired`,
		fmt.Sprintf(msgExpireBody, n, s.ID, s.Service.Hostname, time.Now().Format(format))+hostname(),
	)
}
func (s *Server) actionRevoke(n string) {
	s.notify(
		actionRevoke, `Akcss: VPN `+s.ID+` Profile "`+n+`" was Revoked`,
		fmt.Sprintf(msgRevokeBody, n, s.ID, s.Service.Hostname, time.Now().Format(format), s.Service.Hostname)+hostname(),
	)
}
func (s *Server) actionCreate(n, e string) {
	s.notify(
		actionCreate, `Akcss: VPN `+s.ID+` Profile "`+n+`" was Created`,
		fmt.Sprintf(msgNewBody, n, s.ID, s.Service.Hostname, s.Service.Hostname)+hostname(),
	)
	if len(e) == 0 {
		return
	}
	s.manager.Mail(e, `New VPN Profile "`+n+`" was Created for You`, fmt.Sprintf(msgNewOwnBody, n, s.Service.Hostname))
}
func (a action) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}
func (a *action) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if len(s) == 0 {
		*a = actionAll
		return nil
	}
	var (
		v    string
		p    action
		i, l int
		err  error
	)
	for {
		if l = strings.IndexByte(s[i:], ','); l == -1 {
			v = s[i:]
		} else {
			l += i
			v = s[i:l]
		}
		if p, err = parse(v); err != nil {
			return err
		}
		*a |= p
		if i = l + 1; l <= 0 || l > len(s) {
			break
		}
	}
	return nil
}

// ActionConnect is a function that will send out the connect notification email.
func (s *Server) ActionConnect(n, l, r string) {
	if len(n) == 0 || len(l) == 0 || len(r) == 0 {
		return
	}
	s.notify(
		actionConnect, `Akcss: VPN `+s.ID+` Profile "`+n+`" has Connected`,
		fmt.Sprintf(msgConnectBody, n, s.ID, s.Service.Hostname, time.Now().Format(format), l, r)+hostname(),
	)
}

// ActionDisconnect is a function that will send out the disconnect notification email.
func (s *Server) ActionDisconnect(n, l string, d time.Duration) {
	if len(n) == 0 || d == 0 {
		return
	}
	s.notify(
		actionDisconnect, `Akcss: VPN `+s.ID+` Profile "`+n+`" has Disconnected`,
		fmt.Sprintf(msgDisconnectBody, n, s.ID, s.Service.Hostname, time.Now().Format(format), l, d.String())+hostname(),
	)
}
