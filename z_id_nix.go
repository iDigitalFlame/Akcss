//go:build !windows

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
	"net"
	"syscall"

	"github.com/PurpleSec/logx"
)

func identify(l logx.Log, c net.Conn) error {
	n, ok := c.(*net.UnixConn)
	if !ok {
		return nil
	}
	var (
		u *syscall.Ucred
	)
	f, err := n.File()
	if err != nil {
		l.Error("[daemon/listen] Could not grab file handle of socket: %s!", err.Error())
		return err
	}
	u, err = syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if f.Close(); err != nil {
		l.Error("[daemon/listen] Could get file handle peer creds: %s!", err.Error())
		return err
	}
	l.Trace("[daemon/listen] Connection established by PID: %d/UID: %d!", u.Pid, u.Uid)
	return nil
}
