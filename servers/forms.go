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
	"github.com/kiprotect/go-helpers/forms"
)

// An ID must be between 8 and 32 bytes long
var ID = forms.IsBytes{
	Encoding:  "base64",
	MinLength: 8,
	MaxLength: 32,
}

// A hash ID is always 16 bytes long
var HashID = forms.IsBytes{
	Encoding:  "base64",
	MinLength: 16,
	MaxLength: 16,
}
