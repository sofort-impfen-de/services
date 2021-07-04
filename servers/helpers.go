// Kiebitz - Privacy-Friendly Appointment Scheduling
// Copyright (C) 2021-2021 The Kiebitz Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package servers

import (
	"encoding/base64"
)

// in principle JSON will encode binary data as base64, but we do the conversion
// explicitly just to avoid any potential inconsistencies that might arise in the future...
func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// in principle JSON will encode binary data as base64, but we do the conversion
// explicitly just to avoid any potential inconsistencies that might arise in the future...
func EncodeSlice(data [][]byte) []string {
	strings := make([]string, len(data))
	for i, d := range data {
		strings[i] = base64.StdEncoding.EncodeToString(d)
	}
	return strings
}
