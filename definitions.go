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

package services

import (
	"encoding/json"
)

type Definitions struct {
	CommandsDefinitions
	DatabaseDefinitions
	MeterDefinitions
}

func (d Definitions) Marshal() map[string]interface{} {
	return map[string]interface{}{
		"commands": d.CommandsDefinitions,
		"database": d.DatabaseDefinitions,
		"meters":   d.MeterDefinitions,
	}
}

// We perform JSON marshalling manually to gain more flexibility...
func (d Definitions) MarshalJSON() ([]byte, error) {
	ed := d.Marshal()
	return json.Marshal(ed)
}

func MergeDefinitions(a, b Definitions) Definitions {
	c := Definitions{
		CommandsDefinitions: CommandsDefinitions{},
	}
	for _, obj := range []Definitions{a, b} {
		for _, v := range obj.CommandsDefinitions {
			c.CommandsDefinitions = append(c.CommandsDefinitions, v)
		}
		for k, v := range obj.DatabaseDefinitions {
			c.DatabaseDefinitions[k] = v
		}
		for k, v := range obj.MeterDefinitions {
			c.MeterDefinitions[k] = v
		}
	}
	return c
}
