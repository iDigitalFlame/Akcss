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
	"encoding/json"
	"io/ioutil"
	"sync"
	"sync/atomic"

	"github.com/iDigitalFlame/akcss/vpn"
)

type server struct {
	file string
	lock locker
	*vpn.Server
}
type locker struct {
	state uint32
	sync.Mutex
}
type header struct {
	ID string `json:"id"`
}

func (l *locker) Lock() {
	atomic.StoreUint32(&l.state, 1)
	l.Mutex.Lock()
}
func (l *locker) Unlock() {
	l.Mutex.Unlock()
	atomic.StoreUint32(&l.state, 0)
}
func (s *server) Save() error {
	b, err := json.MarshalIndent(s, "", "    ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.file, b, 0600)
}
func (l *locker) Locked() bool {
	return atomic.LoadUint32(&l.state) == 1
}
