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

/*
import (
	"fmt"
	"github.com/go-redis/redis"
	"github.com/kiprotect/go-helpers/forms"
	"github.com/kiprotect/kodex-ee"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RedisDatabase struct {
	client  redis.UniversalClient
	options redis.UniversalOptions
}

var RedisDatabaseForm = forms.Form{
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

func MakeRedisDatabase(config map[string]interface{}) (*RedisDatabase, error) {

	params, err := RedisDatabaseForm.Validate(config)
	if err != nil {
		return nil, err
	}

	options := redis.UniversalOptions{
		Password:     params["password"].(string),
		ReadTimeout:  time.Second * 1.0,
		WriteTimeout: time.Second * 1.0,
		Addrs:        params["addresses"].([]string),
		DB:           int(params["database"].(int64)),
	}

	client := redis.NewUniversalClient(&options)

	if _, err := client.Ping().Result(); err != nil {
		return nil, err
	}

	database := &RedisDatabase{
		options: options,
		client:  client,
	}

	return database, nil

}

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

func (r *RedisDatabase) Teardown() error {
	client := r.client
	r.client = nil
	return client.Close()
}

func (r *RedisDatabase) Get(table string, key []byte) ([][]byte, error) {
	return nil, nil
}

func (r *RedisDatabase) Set(table string, key, value []byte, ttl time.Duration) error {
	return nil
}

func (r *RedisDatabase) Append(table string, key, value []byte, ttl time.Duration) error {
	return nil
}

func (r *RedisDatabase) DeleteAll(table string, key []byte) error {
	return nil
}

func (r *RedisDatabase) DeleteByValue(table string, key, value []byte) error {
	return nil
}

func (r *RedisDatabase) DeleteBySha256(table string, key, hash []byte) error {
	return nil
}
*/
