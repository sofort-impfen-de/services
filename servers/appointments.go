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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/kiebitz-oss/services"
	"github.com/kiebitz-oss/services/crypto"
	"github.com/kiebitz-oss/services/databases"
	kbForms "github.com/kiebitz-oss/services/forms"
	"github.com/kiebitz-oss/services/jsonrpc"
	"github.com/kiprotect/go-helpers/forms"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Appointments struct {
	server   *jsonrpc.JSONRPCServer
	db       services.Database
	meter    services.Meter
	settings *services.AppointmentsSettings
}

func MakeAppointments(settings *services.Settings) (*Appointments, error) {

	Appointments := &Appointments{
		db:       settings.DatabaseObj,
		meter:    settings.MeterObj,
		settings: settings.Appointments,
	}

	methods := map[string]*jsonrpc.Method{
		"confirmProvider": {
			Form:    &ConfirmProviderForm,
			Handler: Appointments.confirmProvider,
		},
		"addMediatorPublicKeys": {
			Form:    &AddMediatorPublicKeysForm,
			Handler: Appointments.addMediatorPublicKeys,
		},
		"setQueues": {
			Form:    &SetQueuesForm,
			Handler: Appointments.setQueues,
		},
		"getQueues": {
			Form:    &GetQueuesForm,
			Handler: Appointments.getQueues,
		},
		"getQueuesForProvider": {
			Form:    &GetQueuesForProviderForm,
			Handler: Appointments.getQueuesForProvider,
		},
		"addCodes": {
			Form:    &AddCodesForm,
			Handler: Appointments.addCodes,
		},
		"getStats": {
			Form:    &GetStatsForm,
			Handler: Appointments.getStats,
		},
		"getKeys": {
			Form:    &GetKeysForm,
			Handler: Appointments.getKeys,
		},
		"deleteData": {
			Form:    &DeleteDataForm,
			Handler: Appointments.deleteData,
		},
		"getData": {
			Form:    &GetDataForm,
			Handler: Appointments.getData,
		},
		"bulkGetData": {
			Form:    &BulkGetDataForm,
			Handler: Appointments.bulkGetData,
		},
		"bulkStoreData": {
			Form:    &BulkStoreDataForm,
			Handler: Appointments.bulkStoreData,
		},
		"storeData": {
			Form:    &StoreDataForm,
			Handler: Appointments.storeData,
		},
		"getToken": {
			Form:    &GetTokenForm,
			Handler: Appointments.getToken,
		},
		"getQueueTokens": {
			Form:    &GetQueueTokensForm,
			Handler: Appointments.getQueueTokens,
		},
		"storeProviderData": {
			Form:    &StoreProviderDataForm,
			Handler: Appointments.storeProviderData,
		},
		"markTokenAsUsed": {
			Form:    &MarkTokenAsUsedForm,
			Handler: Appointments.markTokenAsUsed,
		},
		"getPendingProviderData": {
			Form:    &GetPendingProviderDataForm,
			Handler: Appointments.getPendingProviderData,
		},
	}

	handler, err := jsonrpc.MethodsHandler(methods)

	if err != nil {
		return nil, err
	}

	if jsonrpcServer, err := jsonrpc.MakeJSONRPCServer(settings.Appointments.RPC, handler); err != nil {
		return nil, err
	} else {
		Appointments.server = jsonrpcServer
		return Appointments, nil
	}
}

func (c *Appointments) Start() error {
	return c.server.Start()
}

func (c *Appointments) Stop() error {
	return c.server.Stop()
}

// Method Handlers

func (c *Appointments) priorityToken() (uint64, []byte, error) {
	data := c.db.Value("priorityToken", []byte("primary"))
	if token, err := data.Get(); err != nil && err != databases.NotFound {
		return 0, nil, err
	} else {
		var intToken uint64
		if err == nil {
			intToken = binary.LittleEndian.Uint64(token)
		}
		intToken = intToken + 1
		bs := make([]byte, 8)
		binary.LittleEndian.PutUint64(bs, intToken)

		if err := data.Set(bs, 0); err != nil {
			return 0, nil, err
		}

		h := hmac.New(sha256.New, c.settings.Secret)
		h.Write(bs)

		token := h.Sum(nil)

		return intToken, token[:], nil

	}
}

type JSON struct {
	Key string
}

func (j JSON) Validate(value interface{}, values map[string]interface{}) (interface{}, error) {
	var jsonValue interface{}
	if err := json.Unmarshal([]byte(value.(string)), &jsonValue); err != nil {
		return nil, err
	}
	// we assign the original value to the given key
	if j.Key != "" {
		values[j.Key] = value
	}
	return jsonValue, nil
}

var ConfirmProviderForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &ConfirmProviderDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var ConfirmProviderDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "encryptedProviderData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &kbForms.ECDHEncryptedDataForm,
				},
			},
		},
		{
			Name: "signedKeyData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &SignedKeyDataForm,
				},
			},
		},
	},
}

var SignedKeyDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &KeyDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 30,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 30,
				},
			},
		},
	},
}

var KeyDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "signing",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 30,
				},
			},
		},
		{
			Name: "encryption",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 30,
				},
			},
		},
		{
			Name: "zipCode",
			Validators: []forms.Validator{
				forms.IsString{
					MaxLength: 5,
					MinLength: 5,
				},
			},
		},
		{
			Name: "queues",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						ID,
					},
				},
			},
		},
	},
}

type ConfirmProviderParams struct {
	JSON      string               `json:"json"`
	Data      *ConfirmProviderData `json:"data"`
	Signature []byte               `json:"signature"`
	PublicKey []byte               `json:"publicKey"`
}

type ConfirmProviderData struct {
	ID                    []byte                      `json:"id"`
	EncryptedProviderData *services.ECDHEncryptedData `json:"encryptedProviderData"`
	SignedKeyData         *SignedKeyData              `json:"signedKeyData"`
}

type SignedKeyData struct {
	JSON      string   `json:"json"`
	Data      *KeyData `json:"data"`
	Signature []byte   `json:"signature"`
	PublicKey []byte   `json:"publicKey"`
}

type KeyData struct {
	Signing    []byte   `json:"signing"`
	Encryption []byte   `json:"encryption"`
	ZipCode    string   `json:"zipCode"`
	Queues     [][]byte `json:"queues"`
}

// { id, key, providerData, keyData }, keyPair
func (c *Appointments) confirmProvider(context *jsonrpc.Context, params *ConfirmProviderParams) *jsonrpc.Response {

	if resp, _ := c.isMediator(context, []byte(params.JSON), params.Signature, params.PublicKey); resp != nil {
		return resp
	}

	hash := crypto.Hash(params.Data.SignedKeyData.Data.Signing)
	keys := c.db.Map("keys", []byte("providers"))

	bd, err := json.Marshal(
		&ActorKey{
			Data:      params.Data.SignedKeyData.JSON,
			Signature: params.Data.SignedKeyData.Signature,
			PublicKey: params.Data.SignedKeyData.PublicKey,
		})
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	if err := keys.Set(hash, bd); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if result, err := keys.Get(hash); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !bytes.Equal(result, bd) {
		services.Log.Error("does not match")
		return context.InternalError()
	}

	data := c.db.Value("data", params.Data.ID)

	pd, err := json.Marshal(params.Data.EncryptedProviderData)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	if err := data.Set(pd, time.Hour*24*365); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	return context.Acknowledge()
}

var AddMediatorPublicKeysForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &AddMediatorPublicKeysDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var AddMediatorPublicKeysDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{
					Format: "rfc3339",
				},
			},
		},
		{
			Name: "encryption",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding: "base64",
				},
			},
		},
		{
			Name: "signing",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding: "base64",
				},
			},
		},
	},
}

type AddMediatorPublicKeysParams struct {
	JSON      string                     `json:"json"`
	Data      *AddMediatorPublicKeysData `json:"data"`
	Signature []byte                     `json:"signature"`
	PublicKey []byte                     `json:"publicKey"`
}

type AddMediatorPublicKeysData struct {
	Timestamp  *time.Time `json:"timestamp"`
	Encryption []byte     `json:"encryption"`
	Signing    []byte     `json:"signing"`
}

// { keys }, keyPair
// add the mediator key to the list of keys (only for testing)
func (c *Appointments) addMediatorPublicKeys(context *jsonrpc.Context, params *AddMediatorPublicKeysParams) *jsonrpc.Response {
	rootKey := c.settings.Key("root")
	if rootKey == nil {
		services.Log.Error("root key missing")
		return context.InternalError()
	}
	if ok, err := rootKey.Verify(&services.SignedData{
		Data:      []byte(params.JSON),
		Signature: params.Signature,
	}); !ok {
		return context.Error(403, "invalid signature", nil)
	} else if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if expired(params.Data.Timestamp) {
		return context.Error(410, "signature expired", nil)
	}
	hash := crypto.Hash(params.Data.Signing)
	keys := c.db.Map("keys", []byte("mediators"))
	bd, err := json.Marshal(context.Request.Params)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if err := keys.Set(hash, bd); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if result, err := keys.Get(hash); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !bytes.Equal(result, bd) {
		services.Log.Error("does not match")
		return context.InternalError()
	}
	return context.Acknowledge()
}

// admin endpoints

var AddCodesForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &CodesDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var CodesDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{
					Format: "rfc3339",
				},
			},
		},
		{
			Name: "actor",
			Validators: []forms.Validator{
				forms.IsString{},
				forms.IsIn{Choices: []interface{}{"provider", "user"}},
			},
		},
		{
			Name: "codes",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsBytes{
							Encoding:  "hex",
							MaxLength: 32,
							MinLength: 16,
						},
					},
				},
			},
		},
	},
}

type AddCodesParams struct {
	JSON      string     `json:"json"`
	Data      *CodesData `json:"data"`
	Signature []byte     `json:"signature"`
	PublicKey []byte     `json:"publicKey"`
}

type CodesData struct {
	Actor     string     `json:"actor"`
	Timestamp *time.Time `json:"timestamp"`
	Codes     [][]byte   `json:"codes"`
}

func (c *Appointments) addCodes(context *jsonrpc.Context, params *AddCodesParams) *jsonrpc.Response {
	rootKey := c.settings.Key("root")
	if rootKey == nil {
		services.Log.Error("root key missing")
		return context.InternalError()
	}
	if ok, err := rootKey.Verify(&services.SignedData{
		Data:      []byte(params.JSON),
		Signature: params.Signature,
	}); !ok {
		return context.Error(403, "invalid signature", nil)
	} else if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if expired(params.Data.Timestamp) {
		return context.Error(410, "signature expired", nil)
	}
	codes := c.db.Set("codes", []byte(params.Data.Actor))
	for _, code := range params.Data.Codes {
		if err := codes.Add(code); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}
	return context.Acknowledge()
}

var SetQueuesForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &QueuesDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var QueuesDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{
					Format: "rfc3339",
				},
			},
		},
		{
			Name: "queues",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &kbForms.QueueForm,
						},
					},
				},
			},
		},
	},
}

type SetQueuesParams struct {
	JSON      string      `json:"json"`
	Data      *QueuesData `json:"data"`
	Signature []byte      `json:"signature"`
	PublicKey []byte      `json:"publicKey"`
}

type QueuesData struct {
	Timestamp *time.Time        `json:"timestamp"`
	Queues    []*services.Queue `json:"queues"`
}

// signed requests are valid only 1 minute
func expired(timestamp *time.Time) bool {
	return time.Now().Add(-time.Minute).After(*timestamp)
}

func (c *Appointments) setQueues(context *jsonrpc.Context, params *SetQueuesParams) *jsonrpc.Response {
	rootKey := c.settings.Key("root")
	if rootKey == nil {
		services.Log.Error("root key missing")
		return context.InternalError()
	}
	if ok, err := rootKey.Verify(&services.SignedData{
		Data:      []byte(params.JSON),
		Signature: params.Signature,
	}); !ok {
		return context.Error(403, "invalid signature", nil)
	} else if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if expired(params.Data.Timestamp) {
		return context.Error(410, "signature expired", nil)
	}
	queues := c.db.Value("queues", []byte("primary"))
	bd, err := json.Marshal(params.Data)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if err := queues.Set(bd, 0); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}
	if result, err := queues.Get(); err != nil {
		return context.InternalError()
	} else if !bytes.Equal(result, bd) {
		return context.InternalError()
	}
	return context.Acknowledge()
}

// public endpoints

var GetQueuesForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "zipCode",
			Validators: []forms.Validator{
				forms.IsString{
					MinLength: 5,
					MaxLength: 5,
				},
			},
		},
		{
			Name: "radius",
			Validators: []forms.Validator{
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    0,
					Max:    50,
				},
			},
		},
	},
}

type GetQueuesParams struct {
	ZipCode string `json:"zipCode"`
	Radius  int64  `json:"radius"`
}

func toStringMap(data []byte) (map[string]interface{}, error) {
	var v map[string]interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func toInterface(data []byte) (interface{}, error) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func (c *Appointments) getQueuesData() (*QueuesData, error) {
	queues := c.db.Value("queues", []byte("primary"))
	if result, err := queues.Get(); err != nil {
		return nil, err
	} else if m, err := toStringMap(result); err != nil {
		return nil, err
	} else if dataParams, err := QueuesDataForm.Validate(m); err != nil {
		return nil, err
	} else {
		queues := &QueuesData{}
		if err := QueuesDataForm.Coerce(queues, dataParams); err != nil {
			return nil, err
		}
		return queues, nil
	}
}

// { zipCode, radius }
func (c *Appointments) getQueues(context *jsonrpc.Context, params *GetQueuesParams) *jsonrpc.Response {
	if queues, err := c.getQueuesData(); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		relevantQueues := []*services.Queue{}
		for _, queue := range queues.Queues {
			if queue.Type == "zipArea" && strings.HasPrefix(params.ZipCode, queue.Name) {
				// we remove the encrypted private key from the queue
				queue.EncryptedPrivateKey = nil
				relevantQueues = append(relevantQueues, queue)
			}
		}
		return context.Result(relevantQueues)
	}
}

type GetKeysParams struct {
}

var GetKeysForm = forms.Form{
	Fields: []forms.Field{},
}

type Keys struct {
	Lists        *KeyLists `json:"lists"`
	ProviderData []byte    `json:"providerData"`
	RootKey      []byte    `json:"rootKey"`
	TokenKey     []byte    `json:"tokenKey"`
}

type KeyLists struct {
	Providers []*ActorKey `json:"providers"`
	Mediators []*ActorKey `json:"mediators"`
}

type ActorKey struct {
	Data      string        `json:"data"`
	Signature []byte        `json:"signature"`
	PublicKey []byte        `json:"publicKey"`
	data      *ActorKeyData `json:"-"`
}

func (a *ActorKey) KeyData() (*ActorKeyData, error) {
	var akd *ActorKeyData
	if a.data != nil {
		return a.data, nil
	}
	if err := json.Unmarshal([]byte(a.Data), &akd); err != nil {
		return nil, err
	}
	a.data = akd
	return akd, nil
}

func (a *ActorKey) ProviderKeyData() (*ProviderKeyData, error) {
	var pkd *ProviderKeyData
	if err := json.Unmarshal([]byte(a.Data), &pkd); err != nil {
		return nil, err
	}
	return pkd, nil
}

type ActorKeyData struct {
	Encryption []byte     `json:"encryption"`
	Signing    []byte     `json:"signing"`
	Timestamp  *time.Time `json:"timestamp"`
}

type ProviderKeyData struct {
	Encryption []byte     `json:"encryption"`
	Signing    []byte     `json:"signing"`
	Queues     [][]byte   `json:"queues"`
	ZipCode    string     `json:"zipCode"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
}

func findActorKey(keys []*ActorKey, publicKey []byte) (*ActorKey, error) {
	for _, key := range keys {
		if akd, err := key.KeyData(); err != nil {
			services.Log.Error(err)
			continue
		} else if bytes.Equal(akd.Signing, publicKey) {
			return key, nil
		}
	}
	return nil, nil
}

func (c *Appointments) getListKeys(key string) ([]*ActorKey, error) {
	mk, err := c.db.Map("keys", []byte(key)).GetAll()

	if err != nil {
		return nil, err
	}

	actorKeys := []*ActorKey{}

	for _, v := range mk {
		var m *ActorKey
		if err := json.Unmarshal(v, &m); err != nil {
			services.Log.Error(err)
			continue
		} else {
			actorKeys = append(actorKeys, m)
		}
	}

	return actorKeys, nil

}

func (c *Appointments) getKeysData() (*Keys, error) {

	mediatorKeys, err := c.getListKeys("mediators")

	if err != nil {
		return nil, err
	}

	providerKeys, err := c.getListKeys("providers")

	if err != nil {
		return nil, err
	}

	return &Keys{
		Lists: &KeyLists{
			Providers: providerKeys,
			Mediators: mediatorKeys,
		},
		ProviderData: c.settings.Key("providerData").PublicKey,
		RootKey:      c.settings.Key("root").PublicKey,
		TokenKey:     c.settings.Key("token").PublicKey,
	}, nil

}

// return all public keys present in the system
func (c *Appointments) getKeys(context *jsonrpc.Context, params *GetKeysParams) *jsonrpc.Response {

	keys, err := c.getKeysData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	return context.Result(keys)
}

// data endpoints

var DeleteDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &DeleteDataDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var DeleteDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}

type DeleteDataParams struct {
	JSON      string          `json:"json"`
	Data      *DeleteDataData `json:"data"`
	Signature []byte          `json:"signature"`
	PublicKey []byte          `json:"publicKey"`
}

type DeleteDataData struct {
	ID []byte `json:"id"`
}

// { id }, keyPair
func (c *Appointments) deleteData(context *jsonrpc.Context, params *DeleteDataParams) *jsonrpc.Response {
	return context.NotFound()
}

var GetDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &GetDataDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var GetDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}

type GetDataParams struct {
	JSON      string       `json:"json"`
	Data      *GetDataData `json:"data"`
	Signature []byte       `json:"signature"`
	PublicKey []byte       `json:"publicKey"`
}

type GetDataData struct {
	ID []byte `json:"id"`
}

// { id }, keyPair
func (c *Appointments) getData(context *jsonrpc.Context, params *GetDataParams) *jsonrpc.Response {
	if data, err := c.db.Value("data", params.Data.ID).Get(); err != nil {
		if err == databases.NotFound {
			return context.NotFound()
		}
		services.Log.Error(err)
		return context.InternalError()
	} else if i, err := toInterface(data); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		return context.Result(i)
	}
}

var BulkGetDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &BulkGetDataDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var BulkGetDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "ids",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						ID,
					},
				},
			},
		},
	},
}

type BulkGetDataParams struct {
	JSON      string           `json:"json"`
	Data      *BulkGetDataData `json:"data"`
	Signature []byte           `json:"signature"`
	PublicKey []byte           `json:"publicKey"`
}

type BulkGetDataData struct {
	IDs [][]byte `json:"ids"`
}

// { ids }, keyPair
func (c *Appointments) bulkGetData(context *jsonrpc.Context, params *BulkGetDataParams) *jsonrpc.Response {
	results := []interface{}{}
	for _, id := range params.Data.IDs {
		if data, err := c.db.Value("data", id).Get(); err != nil {
			if err == databases.NotFound {
				results = append(results, nil)
				continue
			}
			services.Log.Error(err)
			return context.InternalError()
		} else if i, err := toInterface(data); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else {
			results = append(results, i)
		}
	}
	return context.Result(results)
}

var BulkStoreDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &BulkStoreDataDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var BulkStoreDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "dataList",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &StoreDataDataForm,
						},
					},
				},
			},
		},
	},
}

type BulkStoreDataParams struct {
	JSON      string             `json:"json"`
	Data      *BulkStoreDataData `json:"data"`
	Signature []byte             `json:"signature"`
	PublicKey []byte             `json:"publicKey"`
}

type BulkStoreDataData struct {
	DataList []*StoreDataData `json:"dataList"`
}

type StoreDataData struct {
	ID          []byte        `json:"id"`
	Data        interface{}   `json:"data"`
	Permissions []*Permission `json:"permissions"`
	Grant       *Grant        `json:"grant"`
}

type Permission struct {
}

type Grant struct {
}

// { dataList }, keyPair
func (c *Appointments) bulkStoreData(context *jsonrpc.Context, params *BulkStoreDataParams) *jsonrpc.Response {
	for _, sdd := range params.Data.DataList {
		if dv, err := json.Marshal(sdd.Data); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else if err := c.db.Value("data", sdd.ID).Set(dv, time.Hour*24*120); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}
	return context.Acknowledge()
}

var StoreDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &StoreDataDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

type IsAnything struct{}

func (a IsAnything) Validate(value interface{}, values map[string]interface{}) (interface{}, error) {
	return value, nil
}

var StoreDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "data",
			Validators: []forms.Validator{
				IsAnything{},
			},
		},
		{
			Name: "permissions",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &PermissionForm,
						},
					},
				},
			},
		},
		{
			Name: "grant",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{
					Form: &GrantForm,
				},
			},
		},
	},
}

var PermissionForm = forms.Form{
	Fields: []forms.Field{},
}

var GrantForm = forms.Form{
	Fields: []forms.Field{},
}

type StoreDataParams struct {
	JSON      string         `json:"json"`
	Data      *StoreDataData `json:"data"`
	Signature []byte         `json:"signature"`
	PublicKey []byte         `json:"publicKey"`
}

// { id, data, permissions, grant }, keyPair
// store provider data for verification
func (c *Appointments) storeData(context *jsonrpc.Context, params *StoreDataParams) *jsonrpc.Response {
	if dv, err := json.Marshal(params.Data.Data); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if err := c.db.Value("data", params.Data.ID).Set(dv, time.Hour*24*120); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		return context.Acknowledge()
	}
}

// user endpoints

var GetTokenForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "hash",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "queueID",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "code",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "hex", // we encode this as hex since it gets passed in URLs
					MinLength: 16,
					MaxLength: 32,
				},
			},
		},
		{
			Name: "queueData",
			Validators: []forms.Validator{
				forms.IsStringMap{}, // to do: better validation
			},
		},
		{
			Name: "signedTokenData",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{
					Form: &SignedTokenDataForm,
				},
			},
		},
		{
			Name: "encryptedData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &kbForms.ECDHEncryptedDataForm,
				},
			},
		},
	},
}

var SignedTokenDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &TokenDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var TokenDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "hash",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "token",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}

type GetTokenParams struct {
	Hash            []byte                      `json:"hash"`
	EncryptedData   *services.ECDHEncryptedData `json:"encryptedData"`
	QueueID         []byte                      `json:"queueID"`
	Code            []byte                      `json:"code"`
	QueueData       map[string]interface{}      `json:"queueData"`
	SignedTokenData *SignedTokenData            `json:"signedTokenData"`
}

type SignedTokenData struct {
	JSON      string     `json:"json"`
	Data      *TokenData `json:"data"`
	Signature []byte     `json:"signature"`
	PublicKey []byte     `json:"publicKey"`
}

type TokenData struct {
	Token []byte `json:"token"`
	Hash  []byte `json:"hash"`
}

type QueueToken struct {
	Token         []byte                      `json:"token"`
	Queue         []byte                      `json:"queue"`
	Position      int64                       `json:"position"`
	QueueData     map[string]interface{}      `json:"queueData"`
	EncryptedData *services.ECDHEncryptedData `json:"encryptedData"`
}

//{hash, encryptedData, queueID, queueData, signedTokenData}
// get a token for a given queue
// to do: handle updating tokens (necessary?)
func (c *Appointments) getToken(context *jsonrpc.Context, params *GetTokenParams) *jsonrpc.Response {

	codes := c.db.Set("codes", []byte("user"))

	if c.settings.UserCodesEnabled {
		if params.Code == nil {
			return context.Error(400, "code missing", nil)
		}
		if ok, err := codes.Has(params.Code); err != nil {
			services.Log.Error()
			return context.InternalError()
		} else if !ok {
			return context.Error(401, "not authorized", nil)
		}
	}

	if intToken, token, err := c.priorityToken(); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		tokenData := &TokenData{
			Hash:  params.Hash,
			Token: token,
		}

		tokenKey := c.settings.Key("token")
		if tokenKey == nil {
			services.Log.Error("token key missing")
			return context.InternalError()
		}

		td, err := json.Marshal(tokenData)

		if err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}

		if signedData, err := tokenKey.SignString(string(td)); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else {
			queueToken := &QueueToken{
				Position:      int64(intToken),
				Token:         token,
				QueueData:     params.QueueData,
				EncryptedData: params.EncryptedData,
			}
			qd, err := json.Marshal(queueToken)
			if err != nil {
				services.Log.Error(err)
				return context.InternalError()
			}

			ss := c.db.SortedSet("tokens::queued", params.QueueID)

			if err := ss.Add(qd, int64(intToken)); err != nil {
				services.Log.Error(err)
				return context.InternalError()
			}

			// we delete the user code
			if c.settings.UserCodesEnabled {
				if err := codes.Del(params.Code); err != nil {
					services.Log.Error(err)
					return context.InternalError()
				}
			}
			return context.Result(signedData)
		}
	}
}

// provider-only endpoints

var GetQueueTokensForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &GetQueueTokensDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var GetQueueTokensDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "capacities",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &CapacityForm,
						},
					},
				},
			},
		},
	},
}

var CapacityForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "n",
			Validators: []forms.Validator{
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    1,
					Max:    100,
				},
			},
		},
		{
			Name: "properties",
			Validators: []forms.Validator{
				forms.IsStringMap{},
			},
		},
	},
}

type GetQueueTokensParams struct {
	JSON      string              `json:"json"`
	Data      *GetQueueTokensData `json:"data"`
	Signature []byte              `json:"signature"`
	PublicKey []byte              `json:"publicKey"`
}

type GetQueueTokensData struct {
	Capacities []*Capacity `json:"capacities"`
}

type Capacity struct {
	N          int64                  `json:"n"`
	Properties map[string]interface{} `json:"properties"`
}

var tws = []services.TimeWindowFunc{
	services.Minute,
	services.Hour,
	services.Day,
	services.Week,
}

// { capacities }, keyPair
// get n tokens from the given queue IDs
func (c *Appointments) getQueueTokens(context *jsonrpc.Context, params *GetQueueTokensParams) *jsonrpc.Response {

	// make sure this is a valid provider asking for tokens
	resp, providerKey := c.isProvider(context, []byte(params.JSON), params.Signature, params.PublicKey)

	if resp != nil {
		return resp
	}

	allTokens := [][]*QueueToken{}

	pkd, err := providerKey.ProviderKeyData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	var totalCapacity, totalTokens int64
	// to do: better balancing and check queue data
	for _, capacity := range params.Data.Capacities {
		totalCapacity += capacity.N
		tokens := []*QueueToken{}
		for len(tokens) < int(capacity.N) {
			addedTokens := 0
			for _, queueID := range pkd.Queues {
				ssq := c.db.SortedSet("tokens::queued", []byte(queueID))
				sss := c.db.SortedSet("tokens::selected", []byte(queueID))
				if entries, err := ssq.PopMin(capacity.N); err != nil {
					services.Log.Error(err)
					continue
				} else {
					for _, entry := range entries {
						var qt *QueueToken
						if err := json.Unmarshal(entry.Data, &qt); err != nil {
							continue
						}
						qt.Queue = queueID
						// we add the token to the selected tokens for this queue
						if err := sss.Add(entry.Data, entry.Score); err != nil {
							services.Log.Error(err)
						}
						tokens = append(tokens, qt)
						addedTokens += 1
					}
				}
			}
			// no more tokens left it seems
			if addedTokens == 0 {
				break
			}
		}
		totalTokens += int64(len(tokens))
		allTokens = append(allTokens, tokens)
	}

	if c.meter != nil {

		// by convention all values in the meter DB are hex-encoded
		uid := hex.EncodeToString(crypto.Hash(params.PublicKey))

		now := time.Now().UTC().UnixNano()

		addTokenStats := func(tw services.TimeWindow, data map[string]string) error {
			// we add the number of tokens that were returned
			if err := c.meter.Add("queues", "tokens", uid, data, tw, totalTokens); err != nil {
				return err
			}
			// we add the maximum of capacity that a given provider had
			if err := c.meter.AddMax("queues", "capacities", uid, data, tw, totalCapacity); err != nil {
				return err
			}
			// we add the maximum of the difference between capacity and available tokens
			if err := c.meter.AddMax("queues", "oversupply", uid, data, tw, totalCapacity-totalTokens); err != nil {
				return err
			}
			return nil
		}

		for _, twt := range tws {

			// generate the time window
			tw := twt(now)

			// global statistics
			if err := addTokenStats(tw, map[string]string{}); err != nil {
				services.Log.Error(err)
			}

			// statistics by zip code
			if err := addTokenStats(tw, map[string]string{
				"zipCode": pkd.ZipCode,
			}); err != nil {
				services.Log.Error(err)
			}

		}

	}

	return context.Result(allTokens)
}

var StoreProviderDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &StoreProviderDataDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var StoreProviderDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "code",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "hex", // we encode this as hex since it gets passed in URLs
					MinLength: 16,
					MaxLength: 32,
				},
			},
		},
		{
			Name: "encryptedData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &kbForms.ECDHEncryptedDataForm,
				},
			},
		},
	},
}

type StoreProviderDataParams struct {
	JSON      string                 `json:"json"`
	Data      *StoreProviderDataData `json:"data"`
	Signature []byte                 `json:"signature"`
	PublicKey []byte                 `json:"publicKey"`
}

type StoreProviderDataData struct {
	ID            []byte                      `json:"id"`
	EncryptedData *services.ECDHEncryptedData `json:"encryptedData"`
	Code          []byte                      `json:"code"`
}

// { id, encryptedData, code }, keyPair
func (c *Appointments) storeProviderData(context *jsonrpc.Context, params *StoreProviderDataParams) *jsonrpc.Response {

	providerData := c.db.Map("providerData", []byte("unverified"))

	if c.settings.ProviderCodesEnabled {
		if params.Data.Code == nil {
			return context.Error(400, "code missing", nil)
		}
		codes := c.db.Set("codes", []byte("provider"))
		if ok, err := codes.Has(params.Data.Code); err != nil {
			services.Log.Error()
			return context.InternalError()
		} else if !ok {
			return context.Error(401, "not authorized", nil)
		}
	}

	if err := providerData.Set(params.Data.ID, []byte(params.JSON)); err != nil {
		return context.InternalError()
	}

	return context.Acknowledge()
}

var MarkTokenAsUsedForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "token",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "secret",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}

type MarkTokenAsUsedParams struct {
	Token  []byte `json:"token"`
	Secret []byte `json:"secret"`
}

// mark a given token as used using its secret
// { token, secret }, keyPair
func (c *Appointments) markTokenAsUsed(context *jsonrpc.Context, params *MarkTokenAsUsedParams) *jsonrpc.Response {
	return context.NotFound()
}

var GetPendingProviderDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &GetPendingProviderDataDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var GetPendingProviderDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "limit",
			Validators: []forms.Validator{
				forms.IsOptional{Default: 20},
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    1,
					Max:    1000,
				},
			},
		},
	},
}

type GetPendingProviderDataParams struct {
	JSON      string                      `json:"json"`
	Data      *GetPendingProviderDataData `json:"data"`
	Signature []byte                      `json:"signature"`
	PublicKey []byte                      `json:"publicKey"`
}

type GetPendingProviderDataData struct {
	N int64 `json:"n"`
}

func (c *Appointments) isMediator(context *jsonrpc.Context, data, signature, publicKey []byte) (*jsonrpc.Response, *ActorKey) {

	keys, err := c.getKeysData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError(), nil
	}

	return c.isOnKeyList(context, data, signature, publicKey, keys.Lists.Mediators)
}

func (c *Appointments) isProvider(context *jsonrpc.Context, data, signature, publicKey []byte) (*jsonrpc.Response, *ActorKey) {

	keys, err := c.getKeysData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError(), nil
	}

	return c.isOnKeyList(context, data, signature, publicKey, keys.Lists.Providers)
}

func (c *Appointments) isOnKeyList(context *jsonrpc.Context, data, signature, publicKey []byte, keyList []*ActorKey) (*jsonrpc.Response, *ActorKey) {

	actorKey, err := findActorKey(keyList, publicKey)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError(), nil
	}

	if actorKey == nil {
		return context.Error(403, "not authorized", nil), nil
	}

	if ok, err := crypto.VerifyWithBytes(data, signature, publicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError(), nil
	} else if !ok {
		return context.Error(401, "invalid signature", nil), nil
	}

	return nil, actorKey

}

// mediator-only endpoint
// { limit }, keyPair
func (c *Appointments) getPendingProviderData(context *jsonrpc.Context, params *GetPendingProviderDataParams) *jsonrpc.Response {

	if resp, _ := c.isMediator(context, []byte(params.JSON), params.Signature, params.PublicKey); resp != nil {
		return resp
	}

	providerData := c.db.Map("providerData", []byte("unverified"))

	pd, err := providerData.GetAll()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	pdEntries := []map[string]interface{}{}

	for _, v := range pd {
		var m map[string]interface{}
		if err := json.Unmarshal(v, &m); err != nil {
			services.Log.Error(err)
			continue
		} else {
			pdEntries = append(pdEntries, m)
		}
	}

	return context.Result(pdEntries)

}

var GetQueuesForProviderForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &GetQueuesForProviderDataForm,
				},
			},
		},
		{
			Name: "signature",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsBytes{
					Encoding:  "base64",
					MaxLength: 1000,
					MinLength: 50,
				},
			},
		},
	},
}

var GetQueuesForProviderDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "queueIDs",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						ID,
					},
				},
			},
		},
	},
}

type GetQueuesForProviderParams struct {
	JSON      string                    `json:"json"`
	Data      *GetQueuesForProviderData `json:"data"`
	Signature []byte                    `json:"signature"`
	PublicKey []byte                    `json:"publicKey"`
}

type GetQueuesForProviderData struct {
	QueueIDs [][]byte `json:"queueIDs"`
}

// mediator-only endpoint
// { queueIDs }, keyPair
func (c *Appointments) getQueuesForProvider(context *jsonrpc.Context, params *GetQueuesForProviderParams) *jsonrpc.Response {

	if resp, _ := c.isMediator(context, []byte(params.JSON), params.Signature, params.PublicKey); resp != nil {
		return resp
	}

	if queues, err := c.getQueuesData(); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		relevantQueues := []*services.Queue{}
		for _, queue := range queues.Queues {
			for _, queueID := range params.Data.QueueIDs {
				if bytes.Equal(queue.ID, queueID) {
					relevantQueues = append(relevantQueues, queue)
					break
				}
			}
		}
		return context.Result(relevantQueues)
	}

}

// stats endpoint

func UsageValidator(values map[string]interface{}, addError forms.ErrorAdder) error {
	if values["from"] != nil && values["to"] == nil || values["to"] != nil && values["from"] == nil {
		return fmt.Errorf("both from and to must be specified")
	}
	if values["from"] != nil && values["n"] != nil {
		return fmt.Errorf("cannot specify both n and from/to")
	}
	if values["n"] == nil && values["from"] == nil {
		return fmt.Errorf("you need to specify either n or from/to")
	}
	if values["from"] != nil {
		fromT := values["from"].(time.Time)
		toT := values["to"].(time.Time)
		if fromT.UnixNano() > toT.UnixNano() {
			return fmt.Errorf("from date must be before to date")
		}
	}
	return nil
}

var GetStatsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"queues"}},
			},
		},
		{
			Name: "type",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"minute", "hour", "day", "week", "month"}},
			},
		},
		{
			Name: "name",
			Validators: []forms.Validator{
				forms.IsOptional{Default: ""},
				forms.MatchesRegex{Regex: regexp.MustCompile(`^[\w\d\-]{0,50}$`)},
			},
		},
		{
			Name: "from",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsTime{Format: "rfc3339", ToUTC: true},
			},
		},
		{
			Name: "to",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsTime{Format: "rfc3339", ToUTC: true},
			},
		},
		{
			Name: "n",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsInteger{HasMin: true, Min: 1, HasMax: true, Max: 500, Convert: true},
			},
		},
	},
	Transforms: []forms.Transform{},
	Validator:  UsageValidator,
}

type GetStatsParams struct {
	ID   string     `json:"id"`
	Type string     `json:"type"`
	Name string     `json:"name"`
	From *time.Time `json:"from"`
	To   *time.Time `json:"to"`
	N    *int64     `json:"n"`
}

type StatsValue struct {
	Name  string            `json:"name"`
	From  time.Time         `json:"from"`
	To    time.Time         `json:"to"`
	Data  map[string]string `json:"data"`
	Value int64             `json:"value"`
}

type Values struct {
	values []*StatsValue
}

func (f Values) Len() int {
	return len(f.values)
}

func (f Values) Less(i, j int) bool {
	r := (f.values[i].From).Sub(f.values[j].From)
	if r < 0 {
		return true
	}
	// if the from times match we compare the names
	if r == 0 {
		if strings.Compare(f.values[i].Name, f.values[j].Name) < 0 {
			return true
		}
	}
	return false
}

func (f Values) Swap(i, j int) {
	f.values[i], f.values[j] = f.values[j], f.values[i]

}

// public endpoint
func (c *Appointments) getStats(context *jsonrpc.Context, params *GetStatsParams) *jsonrpc.Response {

	if c.meter == nil {
		return context.InternalError()
	}

	toTime := time.Now().UTC().UnixNano()

	var metrics []*services.Metric
	var err error

	if params.N != nil {
		metrics, err = c.meter.N(params.ID, toTime, *params.N, params.Name, params.Type)
	} else {
		metrics, err = c.meter.Range(params.ID, params.From.UnixNano(), params.To.UnixNano(), params.Name, params.Type)
	}

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	values := make([]*StatsValue, 0)

	for _, metric := range metrics {
		if metric.Name[0] == '_' {
			// we skip internal metrics (which start with a '_')
			continue
		}

		values = append(values, &StatsValue{
			From:  time.Unix(metric.TimeWindow.From/1e9, metric.TimeWindow.From%1e9).UTC(),
			To:    time.Unix(metric.TimeWindow.To/1e9, metric.TimeWindow.From%1e9).UTC(),
			Name:  metric.Name,
			Value: metric.Value,
			Data:  metric.Data,
		})
	}

	// we store the statistics
	sortableValues := Values{values: values}
	sort.Sort(sortableValues)

	return context.Result(values)
}
