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
	"encoding/json"
	"github.com/kiebitz-oss/services"
	kbForms "github.com/kiebitz-oss/services/forms"
	"github.com/kiebitz-oss/services/jsonrpc"
	"github.com/kiprotect/go-helpers/forms"
	"time"
)

type Appointments struct {
	server   *jsonrpc.JSONRPCServer
	db       services.Database
	settings *services.AppointmentsSettings
}

func MakeAppointments(settings *services.AppointmentsSettings, db services.Database) (*Appointments, error) {

	Appointments := &Appointments{
		db:       db,
		settings: settings,
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

	if jsonrpcServer, err := jsonrpc.MakeJSONRPCServer(settings.RPC, handler); err != nil {
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

var ECDHEncryptedDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "iv",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MinLength: 10,
					MaxLength: 20,
				},
			},
		},
		{
			Name: "iv",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MinLength: 10,
					MaxLength: 20,
				},
			},
		},
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MinLength: 1,
					MaxLength: 200000,
				},
			},
		},
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding:  "base64",
					MinLength: 1,
					MaxLength: 1000,
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
					Form: &ECDHEncryptedDataForm,
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

var KeyDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "signing",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "encryption",
			Validators: []forms.Validator{
				ID,
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
	ID                    []byte             `json:"id"`
	EncryptedProviderData *ECDHEncryptedData `json:"encryptedProviderData"`
	SignedKeyData         *SignedKeyData     `json:"signedKeyData"`
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

type ECDHEncryptedData struct {
	IV        []byte `json:"iv"`
	Data      []byte `json:"data"`
	PublicKey []byte `json:"publicKey"`
}

// { id, key, providerData, keyData }, keyPair
func (c *Appointments) confirmProvider(context *jsonrpc.Context, params *ConfirmProviderParams) *jsonrpc.Response {

	/*
	   let found = false;
	   const keyDataJSON = JSON.parse(signedKeyData.data);
	   const newProviders = [];
	   for (const existingKey of this.keys.providers) {
	       const existingKeyDataJSON = JSON.parse(existingKey.data);
	       if (existingKeyDataJSON.signing === keyDataJSON.signing) {
	           found = true;
	           newProviders.push(signedKeyData);
	       } else {
	           newProviders.push(existingKey);
	       }
	   }
	   if (!found) newProviders.push(signedKeyData);
	   this.keys.providers = newProviders;
	   this.store.set('keys', this.keys);
	   // we store the verified provider data
	   const result = await this.storeData(
	       { id, data: signedProviderData },
	       keyPair
	   );
	   if (!result) return;
	   return {};
	*/

	return context.NotFound()
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
			Name: "encryption",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "signing",
			Validators: []forms.Validator{
				ID,
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
	Encryption []byte `json:"encryption"`
	Signing    []byte `json:"signing"`
}

// { keys }, keyPair
// add the mediator key to the list of keys (only for testing)
func (c *Appointments) addMediatorPublicKeys(context *jsonrpc.Context, params *AddMediatorPublicKeysParams) *jsonrpc.Response {
	return context.NotFound()
}

// admin endpoints

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
					Form: &SetQueuesDataForm,
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

var SetQueuesDataForm = forms.Form{
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
	JSON      string         `json:"json"`
	Data      *SetQueuesData `json:"data"`
	Signature []byte         `json:"signature"`
	PublicKey []byte         `json:"publicKey"`
}

type SetQueuesData struct {
	Timestamp *time.Time `json:"timestamp"`
	Qeues     []*Queue   `json:"queues"`
}

type Queue struct {
	Name string                 `json:"name"`
	Type string                 `json:"type"`
	ID   []byte                 `json:"id"`
	Data map[string]interface{} `json:"data"`
}

func (c *Appointments) setQueues(context *jsonrpc.Context, params *SetQueuesParams) *jsonrpc.Response {
	services.Log.Debugf("'setQueues' called")
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

// { zipCode, radius }
func (c *Appointments) getQueues(context *jsonrpc.Context, params *GetQueuesParams) *jsonrpc.Response {
	return context.InternalError()
}

type GetKeysParams struct {
}

var GetKeysForm = forms.Form{
	Fields: []forms.Field{},
}

// return all public keys present in the system
func (c *Appointments) getKeys(context *jsonrpc.Context, params *GetKeysParams) *jsonrpc.Response {
	return context.Result(map[string]interface{}{
		"lists":        map[string]interface{}{},
		"providerData": c.settings.RootKey("providerData").PublicKey,
		"rootKey":      c.settings.RootKey("root").PublicKey,
		"tokenKey":     c.settings.RootKey("token").PublicKey,
	})
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
	return context.NotFound()
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
	return context.NotFound()
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
	return context.NotFound()
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

var StoreDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name:       "data",
			Validators: []forms.Validator{},
		},
		{
			Name: "permissions",
			Validators: []forms.Validator{
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
	return context.NotFound()
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
			Name: "queueData",
			Validators: []forms.Validator{
				forms.IsStringMap{}, // to do: better validation
			},
		},
		{
			Name: "signedTokenData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &SignedTokenDataForm,
				},
			},
		},
		{
			Name: "encryptedData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &ECDHEncryptedDataForm,
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
	Hash            []byte                 `json:"hash"`
	EncryptedData   *ECDHEncryptedData     `json:"encryptedData"`
	QueueID         []byte                 `json:"queueID"`
	QueueData       map[string]interface{} `json:"queueData"`
	SignedTokenData *SignedTokenData       `json:"signedTokenData"`
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

//{hash, encryptedData, queueID, queueData, signedTokenData}
// get a token for a given queue
func (c *Appointments) getToken(context *jsonrpc.Context, params *GetTokenParams) *jsonrpc.Response {
	return context.NotFound()
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

// { capacities }, keyPair
// get n tokens from the given queue IDs
func (c *Appointments) getQueueTokens(context *jsonrpc.Context, params *GetQueueTokensParams) *jsonrpc.Response {
	return context.NotFound()
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
				forms.IsOptional{Default: ""},
				forms.IsString{
					MaxLength: 32,
				},
			},
		},
		{
			Name: "encryptedData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &ECDHEncryptedDataForm,
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
	ID            []byte             `json:"id"`
	EncryptedData *ECDHEncryptedData `json:"encryptedData"`
	Code          string             `json:"code"`
}

// { id, encryptedData, code }, keyPair
func (c *Appointments) storeProviderData(context *jsonrpc.Context, params *StoreProviderDataParams) *jsonrpc.Response {

	/*
	   const signedData = await sign(
	       keyPair.privateKey,
	       JSON.stringify(encryptedData),
	       keyPair.publicKey
	   );

	   const result = await this.storeData(
	       { id: id, data: signedData },
	       keyPair
	   );
	   if (!result) return;
	   let providerDataList = this.store.get('providers::list');
	   if (providerDataList === null) providerDataList = [];
	   for (const pid of providerDataList) {
	       if (id === pid) return;
	   }
	   providerDataList.push(id);
	   // we update the provider data list
	   this.store.set('providers::list', providerDataList);

	*/
	return context.NotFound()
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
	Limit int64 `json:"limit"`
}

// mediator-only endpoint
// { limit }, keyPair
func (c *Appointments) getPendingProviderData(context *jsonrpc.Context, params *GetPendingProviderDataParams) *jsonrpc.Response {
	return context.NotFound()
}
