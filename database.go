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
	"time"
)

type DatabaseDefinition struct {
	Name              string            `json:"name"`
	Description       string            `json:"description"`
	Maker             DatabaseMaker     `json:"-"`
	SettingsValidator SettingsValidator `json:"-"`
}

type SettingsValidator func(settings map[string]interface{}) (interface{}, error)
type DatabaseDefinitions map[string]DatabaseDefinition
type DatabaseMaker func(settings interface{}) (Database, error)

// A database can deliver and accept message
type Database interface {
	Close() error
	Open() error
	Get(table string, key []byte) ([][]byte, error)
	Set(table string, key, value []byte, ttl time.Duration) error
	Append(table string, key, value []byte, ttl time.Duration) error
	DeleteAll(table string, key []byte) error
	DeleteByValue(table string, key, value []byte) error
	DeleteBySha256(table string, key, hash []byte) error
}

type BaseDatabase struct {
}
