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
	"github.com/go-redis/redis"
	"github.com/kiebitz-oss/services"
	"github.com/kiprotect/go-helpers/forms"
	"time"
)

type Redis struct {
	client  redis.UniversalClient
	options redis.UniversalOptions
}

type RedisSettings struct {
	Addresses []string `json:"addresses`
	Database  int64    `json:"database"`
	Password  string   `json:"password"`
}

var RedisForm = forms.Form{
	ErrorMsg: "invalid data encountered in the Redis config form",
	Fields: []forms.Field{
		{
			Name: "addresses",
			Validators: []forms.Validator{
				forms.IsRequired{},
				forms.IsStringList{},
			},
		},
		{
			Name: "database",
			Validators: []forms.Validator{
				forms.IsOptional{Default: 0},
				forms.IsInteger{Min: 0, Max: 100},
			},
		},
		{
			Name: "password",
			Validators: []forms.Validator{
				forms.IsRequired{},
				forms.IsString{},
			},
		},
	},
}

func ValidateRedisSettings(settings map[string]interface{}) (interface{}, error) {
	if params, err := RedisForm.Validate(settings); err != nil {
		return nil, err
	} else {
		redisSettings := &RedisSettings{}
		if err := RedisForm.Coerce(redisSettings, params); err != nil {
			return nil, err
		}
		return redisSettings, nil
	}
}

func MakeRedis(settings interface{}) (services.Database, error) {

	redisSettings := settings.(RedisSettings)

	options := redis.UniversalOptions{
		Password:     redisSettings.Password,
		ReadTimeout:  time.Second * 1.0,
		WriteTimeout: time.Second * 1.0,
		Addrs:        redisSettings.Addresses,
		DB:           int(redisSettings.Database),
	}

	client := redis.NewUniversalClient(&options)

	if _, err := client.Ping().Result(); err != nil {
		return nil, err
	} else {
		services.Log.Debug("Ping to Redis succeeded!")
	}

	database := &Redis{
		options: options,
		client:  client,
	}

	return database, nil

}

func (d *Redis) Open() error {
	return nil
}

func (d *Redis) Close() error {
	return nil
}

func (d *Redis) Begin() error {
	return nil
}

func (d *Redis) Commit() error {
	return nil
}

func (d *Redis) Rollback() error {
	return nil
}

func (d *Redis) Set(table string, key []byte) services.Set {
	return nil
}
func (d *Redis) SortedSet(table string, key []byte) services.SortedSet {
	return nil
}

func (d *Redis) List(table string, key []byte) services.List {
	return nil
}

func (d *Redis) Map(table string, key []byte) services.Map {
	return nil
}

func (d *Redis) Value(table string, key []byte) services.Value {
	return nil
}

/*

var paramsRegex = regexp.MustCompile(`^([^\()]+)\((.*)\)$`)

func decodeData(value string) (map[string]string, string) {
	matches := paramsRegex.FindStringSubmatch(value)
	if matches == nil {
		return nil, value
	} else {
		m := make(map[string]string)
		parens := matches[2]
		eqns := strings.Split(parens, ",")
		for _, eqn := range eqns {
			kv := strings.SplitN(eqn, "=", 2)
			if len(kv) < 2 {
				return nil, matches[1]
			}
			m[kv[0]] = kv[1]
		}
		return m, matches[1]
	}
}

func (r *Redis) Teardown() error {
	client := r.client
	r.client = nil
	return client.Close()
}

func (r *Redis) Get(table string, key []byte) ([][]byte, error) {
	return nil, nil
}

func (r *Redis) Set(table string, key, value []byte, ttl time.Duration) error {
	return nil
}

func (r *Redis) Append(table string, key, value []byte, ttl time.Duration) error {
	return nil
}

func (r *Redis) DeleteAll(table string, key []byte) error {
	return nil
}

func (r *Redis) DeleteByValue(table string, key, value []byte) error {
	return nil
}

func (r *Redis) DeleteBySha256(table string, key, hash []byte) error {
	return nil
}
*/
