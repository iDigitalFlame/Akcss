//go:build windows

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

package userid

// Nobody will look up and cache the result of the GID for the "nobody" user,
// which is used to set permissions for OpenVPN sessions running with lower
// permissions can read public keys and validate clients.
//
// If the "rootok" build tag was used when compiling, this function will return
// (0, nil) if the lookup for "nobody" fails, which is useful when running in a
// container or a distro that does not have a "nobody" user.
//
// On Windows devices, this function does nothing and always returns (0, nil)
// although it shouldn't be used (hopefully the compiler optimizes it out).
func Nobody() (int, error) {
	return 0, nil
}
