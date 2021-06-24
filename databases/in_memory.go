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

package databases

import (
	"crypto/sha256"
	"github.com/kiebitz-oss/services"
	"time"
)

type TTL struct {
	Key string
	TTL time.Time
}

type InMemory struct {
	Data map[string][][]byte
	TTLs []*TTL
}

// we hash all keys to SHA256 values to limit the storage size
func bhash(key []byte) []byte {
	v := sha256.Sum256(key)
	return v[:]
}

func hash(key []byte) string {
	return string(bhash(key))
}

func fk(table string, key []byte) []byte {
	return append([]byte(table), key...)
}

type InMemorySettings struct {
}

func ValidateInMemorySettings(settings map[string]interface{}) (interface{}, error) {
	return settings, nil
}

func MakeInMemory(settings interface{}) (services.Database, error) {
	return &InMemory{
		Data: make(map[string][][]byte),
		TTLs: make([]*TTL, 0, 100),
	}, nil
}

func (d *InMemory) Open() error {
	return nil
}

func (d *InMemory) Close() error {
	return nil
}

func (d *InMemory) Begin() (services.Transaction, error) {
	return nil, nil
}

func (d *InMemory) Expire(table string, key []byte, ttl int64) error {
	return nil
}

func (d *InMemory) Set(table string, key []byte) services.Set {
	return nil
}
func (d *InMemory) SortedSet(table string, key []byte) services.SortedSet {
	return nil
}

func (d *InMemory) List(table string, key []byte) services.List {
	return nil
}

func (d *InMemory) Map(table string, key []byte) services.Map {
	return nil
}

func (d *InMemory) Value(table string, key []byte) services.Value {
	return nil
}

/*
func (d *InMemory) Get(table string, key []byte) ([][]byte, error) {
	if data, ok := d.Data[hash(fk(table, key))]; !ok {
		return nil, NotFound
	} else {
		return data, nil
	}
}

func (d *InMemory) Set(table string, key, value []byte, ttl time.Duration) error {
	d.Data[hash(fk(table, key))] = [][]byte{value}
	return nil
}

func (d *InMemory) Append(table string, key, value []byte, ttl time.Duration) error {
	k := hash(fk(table, key))
	data, ok := d.Data[k]
	if !ok {
		data = make([][]byte, 0)
	}
	for _, v := range data {
		if bytes.Equal(v, value) {
			// data value is already present under this key
			return nil
		}
	}
	data = append(data, value)
	d.Data[k] = data
	return nil
}

func (d *InMemory) DeleteAll(table string, key []byte) error {
	delete(d.Data, hash(fk(table, key)))
	return nil
}

func (d *InMemory) DeleteByValue(table string, key, value []byte) error {
	k := hash(fk(table, key))
	data, ok := d.Data[k]
	if ok {
		newData := make([][]byte, 0, len(data)-1)
		for _, v := range data {
			if bytes.Equal(v, value) {
				continue
			}
			newData = append(newData, v)
		}
		d.Data[k] = newData
	}
	return nil
}

func (d *InMemory) DeleteBySha256(table string, key, h []byte) error {
	k := hash(fk(table, key))
	data, ok := d.Data[k]
	if ok {
		newData := make([][]byte, 0, len(data)-1)
		for _, v := range data {
			if bytes.Equal(bhash(v), h) {
				continue
			}
			newData = append(newData, v)
		}
		d.Data[k] = newData
	}
	return nil
}
*/
