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

package jsonrpc

import (
	"github.com/kiprotect/go-helpers/forms"
)

var JSONRPCRequestForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "jsonrpc",
			Validators: []forms.Validator{
				forms.IsString{},
				forms.IsIn{
					// we only support JSONRPC-2.0 right now
					Choices: []interface{}{"2.0"},
				},
			},
		},
		{
			Name: "method",
			Validators: []forms.Validator{
				forms.IsString{
					MinLength: 1,
					MaxLength: 100,
				},
			},
		},
		{
			Name: "params",
			Validators: []forms.Validator{
				// we only support string-map style parameter passing
				forms.IsStringMap{},
			},
		},
		{
			Name: "id",
			Validators: []forms.Validator{
				// it may be omitted (then we generate one)
				forms.IsOptional{},
				// either a string or an integer
				forms.Or{
					Options: [][]forms.Validator{
						{
							// we support strings
							forms.IsString{
								MinLength: 1,
								MaxLength: 100,
							},
						},
						{
							// we also support integers
							forms.IsInteger{
								HasMin: true,
								HasMax: true,
								Min:    -2147483648,
								Max:    2147483647,
							},
						},
					},
				},
			},
		},
	},
}
