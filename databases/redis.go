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
	"fmt"
	"github.com/go-redis/redis"
	"github.com/kiebitz-oss/services"
	"github.com/kiprotect/go-helpers/forms"
	"strconv"
	"sync"
	"time"
)

type Redis struct {
	client      redis.UniversalClient
	options     redis.UniversalOptions
	transaction *redis.Tx
	pipeline    redis.Pipeliner
	mutex       sync.Mutex
	channel     chan bool
}

type RedisSettings struct {
	MasterName string   `json:"master_name"`
	Addresses  []string `json:"addresses`
	Database   int64    `json:"database"`
	Password   string   `json:"password"`
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
			Name: "master_name",
			Validators: []forms.Validator{
				forms.IsOptional{Default: ""},
				forms.IsString{},
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
		MasterName:   redisSettings.MasterName,
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
		services.Log.Info("Ping to Redis succeeded!")
	}

	database := &Redis{
		options: options,
		client:  client,
		channel: make(chan bool),
	}

	return database, nil

}

func (d *Redis) Client() redis.Cmdable {
	if d.transaction != nil {
		return d.transaction
	}
	return d.client
}

func (d *Redis) Open() error {
	return nil
}

func (d *Redis) Close() error {
	return d.client.Close()
}

func (d *Redis) Watch(keys ...string) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.transaction == nil {
		return fmt.Errorf("cannot watch keys outside a transaction")
	}

	return d.transaction.Watch(keys...).Err()
}

func (d *Redis) Begin() (services.Transaction, error) {

	if d.transaction != nil {
		return nil, fmt.Errorf("already in a transaction")
	}

	nd := &Redis{
		options: d.options,
		client:  d.client,
		channel: make(chan bool),
	}

	started := make(chan bool)

	tx := func(tx *redis.Tx) error {
		nd.mutex.Lock()
		nd.transaction = tx
		nd.mutex.Unlock()

		started <- true

		_, err := tx.Pipelined(func(pipeline redis.Pipeliner) error {

			nd.mutex.Lock()
			nd.pipeline = pipeline
			nd.mutex.Unlock()

			// we block until the transaction completes
			commit := <-nd.channel

			nd.mutex.Lock()
			if !commit {
				if err := nd.pipeline.Discard(); err != nil {
					services.Log.Error(err)
				}
			}
			nd.mutex.Unlock()

			nd.channel <- commit

			return nil
		})
		return err
	}

	go func() {
		err := nd.client.Watch(tx)
		if err != nil {
			services.Log.Error(err)
		}
	}()

	select {
	case <-started:
	case <-time.After(1 * time.Second):
		return nil, fmt.Errorf("timeout")
	}

	return nd, nil
}

func (d *Redis) Commit() error {

	if d.transaction == nil {
		return fmt.Errorf("not in a transaction")
	}

	// we wait for the transaction to finish
	d.channel <- true
	<-d.channel

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.transaction = nil
	d.pipeline = nil

	return nil
}

func (d *Redis) Rollback() error {

	if d.transaction == nil {
		return fmt.Errorf("not in a transaction")
	}

	// we wait for the transaction to finish
	d.channel <- false
	<-d.channel

	d.mutex.Lock()
	defer d.mutex.Unlock()

	d.transaction = nil
	d.pipeline = nil

	return nil
}

func (d *Redis) Expire(table string, key []byte, ttl time.Duration) error {
	return d.Client().Expire(string(d.fullKey(table, key)), ttl).Err()
}

func (d *Redis) Set(table string, key []byte) services.Set {
	return &RedisSet{
		db:      d,
		fullKey: d.fullKey(table, key),
	}
}
func (d *Redis) SortedSet(table string, key []byte) services.SortedSet {
	return &RedisSortedSet{
		db:      d,
		fullKey: d.fullKey(table, key),
	}
}

func (d *Redis) List(table string, key []byte) services.List {
	return nil
}

func (d *Redis) Map(table string, key []byte) services.Map {
	return &RedisMap{
		db:      d,
		fullKey: d.fullKey(table, key),
	}
}

func (d *Redis) Value(table string, key []byte) services.Value {
	return &RedisValue{
		db:      d,
		fullKey: d.fullKey(table, key),
	}
}

func (d *Redis) fullKey(table string, key []byte) []byte {
	return []byte(fmt.Sprintf("%s::%s", table, string(key)))
}

type RedisMap struct {
	db      *Redis
	fullKey []byte
}

func (r *RedisMap) Del(key []byte) error {
	return r.db.Client().HDel(string(r.fullKey), string(key)).Err()
}

func (r *RedisMap) GetAll() (map[string][]byte, error) {
	result, err := r.db.Client().HGetAll(string(r.fullKey)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, NotFound
		}
		return nil, err
	}
	byteMap := map[string][]byte{}
	for k, v := range result {
		byteMap[k] = []byte(v)
	}
	return byteMap, nil
}

func (r *RedisMap) Get(key []byte) ([]byte, error) {
	result, err := r.db.Client().HGet(string(r.fullKey), string(key)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, NotFound
		}
		return nil, err
	}
	return []byte(result), nil
}

func (r *RedisMap) Set(key []byte, value []byte) error {
	return r.db.Client().HSet(string(r.fullKey), string(key), string(value)).Err()
}

type RedisSet struct {
	db      *Redis
	fullKey []byte
}

func (r *RedisSet) Add(data []byte) error {
	return r.db.Client().SAdd(string(r.fullKey), string(data)).Err()
}

func (r *RedisSet) Has(data []byte) (bool, error) {
	return r.db.Client().SIsMember(string(r.fullKey), string(data)).Result()
}

func (r *RedisSet) Del(data []byte) error {
	return r.db.Client().SRem(string(r.fullKey), string(data)).Err()
}

func (r *RedisSet) Members() ([]*services.SetEntry, error) {
	result, err := r.db.Client().SMembers(string(r.fullKey)).Result()
	if err != nil {
		return nil, err
	}

	var entries []*services.SetEntry

	for _, entry := range result {
		entries = append(entries, &services.SetEntry{
			Data: []byte(entry),
		})
	}
	return entries, nil
}

type RedisValue struct {
	db      *Redis
	fullKey []byte
}

func (r *RedisValue) Set(data []byte, ttl time.Duration) error {
	return r.db.Client().Set(string(r.fullKey), string(data), ttl).Err()
}

func (r *RedisValue) Get() ([]byte, error) {
	result, err := r.db.Client().Get(string(r.fullKey)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, NotFound
		}
		return nil, err
	}
	return []byte(result), nil
}

func (r *RedisValue) Del() error {
	return r.db.Client().Del(string(r.fullKey)).Err()
}

type RedisSortedSet struct {
	db      *Redis
	fullKey []byte
}

func (r *RedisSortedSet) Score(data []byte) (int64, error) {
	n, err := r.db.Client().ZScore(string(r.fullKey), string(data)).Result()
	if err == redis.Nil {
		return 0, NotFound
	} else if err != nil {
		return 0, err
	}
	return int64(n), nil
}

func (r *RedisSortedSet) Add(data []byte, score int64) error {
	return r.db.Client().ZAdd(string(r.fullKey), redis.Z{Score: float64(score), Member: string(data)}).Err()
}

func (r *RedisSortedSet) Del(data []byte) (bool, error) {
	n, err := r.db.Client().ZRem(string(r.fullKey), string(data)).Result()
	return n > 0, err
}

func (r *RedisSortedSet) Range(from, to int64) ([]*services.SortedSetEntry, error) {
	result, err := r.db.Client().ZRangeWithScores(string(r.fullKey), from, to).Result()
	if err != nil {
		return nil, err
	}

	entries := []*services.SortedSetEntry{}

	for _, entry := range result {
		entries = append(entries, &services.SortedSetEntry{
			Score: int64(entry.Score),
			Data:  []byte(entry.Member.(string)),
		})
	}
	return entries, nil
}

func (r *RedisSortedSet) RangeByScore(from, to int64) ([]*services.SortedSetEntry, error) {
	result, err := r.db.Client().ZRangeByScoreWithScores(string(r.fullKey), redis.ZRangeBy{
		Min: strconv.FormatInt(from, 10),
		Max: strconv.FormatInt(to, 10),
	}).Result()
	if err != nil {
		return nil, err
	}

	entries := []*services.SortedSetEntry{}

	for _, entry := range result {
		entries = append(entries, &services.SortedSetEntry{
			Score: int64(entry.Score),
			Data:  []byte(entry.Member.(string)),
		})
	}
	return entries, nil
}

func (r *RedisSortedSet) At(index int64) (*services.SortedSetEntry, error) {
	result, err := r.db.Client().ZRangeWithScores(string(r.fullKey), index, index).Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, NotFound
	}

	z := result[0]

	return &services.SortedSetEntry{
		Score: int64(z.Score),
		Data:  []byte(z.Member.(string)),
	}, nil
}

func (r *RedisSortedSet) PopMin(n int64) ([]*services.SortedSetEntry, error) {
	result, err := r.db.Client().ZPopMin(string(r.fullKey), n).Result()
	if err != nil {
		return nil, err
	}
	entries := []*services.SortedSetEntry{}
	for _, z := range result {
		entries = append(entries, &services.SortedSetEntry{
			Score: int64(z.Score),
			Data:  []byte(z.Member.(string)),
		})
	}
	return entries, nil
}

func (r *RedisSortedSet) RemoveRangeByScore(from, to int64) error {
	_, err := r.db.Client().ZRemRangeByScore(string(r.fullKey), strconv.FormatInt(from, 10), strconv.FormatInt(to, 10)).Result()
	if err != nil {
		return err
	}
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
