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
		"uploadDistances": {
			Form:    &UploadDistancesForm,
			Handler: Appointments.uploadDistances,
		},
		"getStats": {
			Form:    &GetStatsForm,
			Handler: Appointments.getStats,
		},
		"getKeys": {
			Form:    &GetKeysForm,
			Handler: Appointments.getKeys,
		},
		"getAppointmentsByZipCode": {
			Form:    &GetAppointmentsByZipCodeForm,
			Handler: Appointments.getAppointmentsByZipCode,
		},
		"getProviderAppointments": {
			Form:    &GetProviderAppointmentsForm,
			Handler: Appointments.getProviderAppointments,
		},
		"publishAppointments": {
			Form:    &PublishAppointmentsForm,
			Handler: Appointments.publishAppointments,
		},
		"getBookedAppointments": {
			Form:    &GetBookedAppointmentsForm,
			Handler: Appointments.getBookedAppointments,
		},
		"cancelBooking": {
			Form:    &CancelBookingForm,
			Handler: Appointments.cancelBooking,
		},
		"bookSlot": {
			Form:    &BookSlotForm,
			Handler: Appointments.bookSlot,
		},
		"cancelSlot": {
			Form:    &CancelSlotForm,
			Handler: Appointments.cancelSlot,
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
		"storeProviderData": {
			Form:    &StoreProviderDataForm,
			Handler: Appointments.storeProviderData,
		},
		"getPendingProviderData": {
			Form:    &GetPendingProviderDataForm,
			Handler: Appointments.getPendingProviderData,
		},
		"getVerifiedProviderData": {
			Form:    &GetVerifiedProviderDataForm,
			Handler: Appointments.getVerifiedProviderData,
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
			Name: "verifiedID",
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
			Name: "publicProviderData",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{
					Form: &SignedProviderDataForm,
				},
			},
		},
		{
			Name: "signedKeyData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &SignedDataForm,
				},
			},
		},
	},
}

var ProviderDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "name",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "street",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "city",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "zipCode",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
	},
}

var SignedProviderDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &ProviderDataForm,
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
var SignedDataForm = forms.Form{
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
			Name: "queueData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &ProviderQueueDataForm,
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

var ProviderQueueDataForm = forms.Form{
	Fields: []forms.Field{
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
			Name: "accessible",
			Validators: []forms.Validator{
				forms.IsOptional{Default: false},
				forms.IsBoolean{},
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
	VerifiedID            []byte                      `json:"verifiedID"`
	PublicProviderData    *SignedProviderData         `json:"publicProviderData"`
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
	Signing    []byte             `json:"signing"`
	Encryption []byte             `json:"encryption"`
	Queues     [][]byte           `json:"queues"`
	QueueData  *ProviderQueueData `json:"queueData"`
}

type ProviderQueueData struct {
	ZipCode    string `json:"zipCode"`
	Accessible bool   `json:"accessible"`
}

// { id, key, providerData, keyData }, keyPair
func (c *Appointments) confirmProvider(context *jsonrpc.Context, params *ConfirmProviderParams) *jsonrpc.Response {

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	if resp, _ := c.isMediator(context, []byte(params.JSON), params.Signature, params.PublicKey); resp != nil {
		return resp
	}

	hash := crypto.Hash(params.Data.SignedKeyData.Data.Signing)
	keys := transaction.Map("keys", []byte("providers"))

	providerKey := &ActorKey{
		Data:      params.Data.SignedKeyData.JSON,
		Signature: params.Data.SignedKeyData.Signature,
		PublicKey: params.Data.SignedKeyData.PublicKey,
	}

	bd, err := json.Marshal(providerKey)
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
		return context.InternalError()
	}

	data := transaction.Value("data", params.Data.VerifiedID)

	pd, err := json.Marshal(params.Data.EncryptedProviderData)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	ttl := time.Hour * 24 * 365

	if err := data.Set(pd, ttl); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	permissions := []*Permission{
		&Permission{
			Rights: []string{"read"},
			Keys:   [][]byte{params.Data.SignedKeyData.Data.Signing},
		},
	}

	// we give the provider the right to read this data
	if result := c.setPermissions(context, transaction, params.Data.VerifiedID, permissions, params.Data.SignedKeyData.Data.Signing, ttl); result != nil {
		return result
	}

	unverifiedProviderData := transaction.Map("providerData", []byte("unverified"))
	verifiedProviderData := transaction.Map("providerData", []byte("verified"))
	publicProviderData := transaction.Map("providerData", []byte("public"))

	oldPd, err := unverifiedProviderData.Get(params.Data.ID)

	if err != nil {
		if err == databases.NotFound {
			// maybe this provider has already been verified before...
			if oldPd, err = verifiedProviderData.Get(params.Data.ID); err != nil {
				if err == databases.NotFound {
					return context.NotFound()
				} else {
					services.Log.Error(err)
					return context.InternalError()
				}
			}
		} else {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	if err := unverifiedProviderData.Del(params.Data.ID); err != nil {
		if err != databases.NotFound {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	if err := verifiedProviderData.Set(params.Data.ID, oldPd); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	if params.Data.PublicProviderData != nil {
		signedData := map[string]interface{}{
			"data":      params.Data.PublicProviderData.JSON,
			"signature": params.Data.PublicProviderData.Signature,
			"publicKey": params.Data.PublicProviderData.PublicKey,
		}
		if data, err := json.Marshal(signedData); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else if err := publicProviderData.Set(hash, data); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	success = true

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
	if ok, err := rootKey.Verify(&crypto.SignedData{
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
	if ok, err := rootKey.Verify(&crypto.SignedData{
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

var UploadDistancesForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &DistancesDataForm,
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

var DistancesDataForm = forms.Form{
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
			Name: "type",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"zipCode", "zipArea"}},
			},
		},
		{
			Name: "distances",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &DistanceForm,
						},
					},
				},
			},
		},
	},
}

var DistanceForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "from",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "to",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "distance",
			Validators: []forms.Validator{
				forms.IsFloat{
					HasMin: true,
					Min:    0.0,
					HasMax: true,
					Max:    200.0,
				},
			},
		},
	},
}

type UploadDistancesParams struct {
	JSON      string         `json:"json"`
	Data      *DistancesData `json:"data"`
	Signature []byte         `json:"signature"`
	PublicKey []byte         `json:"publicKey"`
}

type DistancesData struct {
	Timestamp *time.Time `json:"timestamp"`
	Type      string     `json:"type"`
	Distances []Distance `json:"distances"`
}

type Distance struct {
	From     string  `json:"from"`
	To       string  `json:"to"`
	Distance float64 `json:"distance"`
}

func (c *Appointments) getDistance(distanceType, from, to string) (float64, error) {

	dst := c.db.Map("distances", []byte(distanceType))
	keyA := fmt.Sprintf("%s:%s", from, to)
	keyB := fmt.Sprintf("%s:%s", to, from)
	value, err := dst.Get([]byte(keyA))

	if err != nil && err != databases.NotFound {
		return 0.0, err
	}

	if value == nil {
		value, err = dst.Get([]byte(keyB))
	}

	if err != nil {
		return 0.0, err
	}

	buf := bytes.NewReader(value)
	var distance float64
	if err := binary.Read(buf, binary.LittleEndian, &distance); err != nil {
		return 0.0, err
	}

	return distance, nil

}

func (c *Appointments) uploadDistances(context *jsonrpc.Context, params *UploadDistancesParams) *jsonrpc.Response {
	rootKey := c.settings.Key("root")
	if rootKey == nil {
		services.Log.Error("root key missing")
		return context.InternalError()
	}
	if ok, err := rootKey.Verify(&crypto.SignedData{
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
	dst := c.db.Map("distances", []byte(params.Data.Type))
	for _, distance := range params.Data.Distances {
		neighborsFrom := c.db.SortedSet(fmt.Sprintf("distances::neighbors::%s", params.Data.Type), []byte(distance.From))
		neighborsTo := c.db.SortedSet(fmt.Sprintf("distances::neighbors::%s", params.Data.Type), []byte(distance.To))
		neighborsFrom.Add([]byte(distance.To), int64(distance.Distance))
		neighborsTo.Add([]byte(distance.From), int64(distance.Distance))
		key := fmt.Sprintf("%s:%s", distance.From, distance.To)
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.LittleEndian, distance.Distance); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
		if err := dst.Set([]byte(key), buf.Bytes()); err != nil {
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
	if ok, err := rootKey.Verify(&crypto.SignedData{
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
		var exactMatch *services.Queue
		for _, queue := range queues.Queues {

			// we remove the encrypted private key from the queue
			queue.EncryptedPrivateKey = nil

			if queue.Type == "zipArea" {

				if params.ZipCode[0:len(queue.Name)] != queue.Name {
					if distance, err := c.getDistance("zipArea", params.ZipCode[0:len(queue.Name)], queue.Name); err != nil {
						if err != databases.NotFound {
							services.Log.Error(err)
						}
						continue
					} else {
						if distance > float64(params.Radius) {
							// the distance is too far
							continue
						}
					}
					relevantQueues = append(relevantQueues, queue)
				} else {
					exactMatch = queue
					continue
				}
			}
		}

		// we make sure the exactly matching queue always gets returned first...
		if exactMatch != nil {
			relevantQueues = append([]*services.Queue{exactMatch}, relevantQueues...)
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
	if pkd.QueueData == nil {
		pkd.QueueData = &ProviderQueueData{}
	}
	return pkd, nil
}

type ActorKeyData struct {
	Encryption []byte     `json:"encryption"`
	Signing    []byte     `json:"signing"`
	Timestamp  *time.Time `json:"timestamp"`
}

type ProviderKeyData struct {
	Encryption []byte             `json:"encryption"`
	Signing    []byte             `json:"signing"`
	Queues     [][]byte           `json:"queues"`
	QueueData  *ProviderQueueData `json:"queueData"`
	Timestamp  *time.Time         `json:"timestamp,omitempty"`
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
		services.Log.Error(err)
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

	providerDataKey := c.settings.Key("provider")

	// to do: remove once the settings are updated
	if providerDataKey == nil {
		providerDataKey = c.settings.Key("providerData")
	}

	return &Keys{
		Lists: &KeyLists{
			Providers: providerKeys,
			Mediators: mediatorKeys,
		},
		ProviderData: providerDataKey.PublicKey,
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

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	// we verify the signature (without veryfing e.g. the provenance of the key)
	if ok, err := crypto.VerifyWithBytes([]byte(params.JSON), params.Signature, params.PublicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	// we make sure the user has the permission to read this data
	if result := c.verifyPermissions(context, transaction, params.Data.ID, []string{"read"}, params.PublicKey, false); result != nil {
		return result
	}

	if data, err := transaction.Value("data", params.Data.ID).Get(); err != nil {
		if err == databases.NotFound {
			return context.NotFound()
		}
		services.Log.Error(err)
		return context.InternalError()
	} else if i, err := toInterface(data); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		success = true
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

	// we verify the signature (without veryfing e.g. the provenance of the key)
	if ok, err := crypto.VerifyWithBytes([]byte(params.JSON), params.Signature, params.PublicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	for _, id := range params.Data.IDs {

		// we make sure the user has the permission to read this data
		if result := c.verifyPermissions(context, transaction, id, []string{"read"}, params.PublicKey, false); result != nil {
			results = append(results, nil)
			continue
		}

		if data, err := transaction.Value("data", id).Get(); err != nil {
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

	success = true

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
	Rights []string `json:"rights"`
	Keys   [][]byte `json:"keys"`
}

type GrantData struct {
	ObjectID    []byte        `json:"objectID"`
	GrantID     []byte        `json:"grantID"`
	Type        string        `json:"type"`
	SingleUse   bool          `json:"singleUse"`
	ExpiresAt   time.Time     `json:"expiresAt"`
	Permissions []*Permission `json:"permissions"`
}

type GrantContext struct {
	SignedTokenData *SignedTokenData `json:"signedTokenData"`
}

type Grant struct {
	JSON      string        `json:"json"`
	Data      *GrantData    `json:"data"`
	Context   *GrantContext `json:"context"`
	Signature []byte        `json:"signature"`
	PublicKey []byte        `json:"publicKey"`
}

// { dataList }, keyPair
func (c *Appointments) bulkStoreData(context *jsonrpc.Context, params *BulkStoreDataParams) *jsonrpc.Response {

	// we verify the signature (without veryfing e.g. the provenance of the key)
	if ok, err := crypto.VerifyWithBytes([]byte(params.JSON), params.Signature, params.PublicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	responses := make([]*jsonrpc.Error, 0)

	for _, sdd := range params.Data.DataList {
		if response := c.storeDataHelper(context, params.JSON, params.PublicKey, params.Signature, sdd); response != nil {
			responses = append(responses, response.Error)
		} else {
			responses = append(responses, nil)
		}
	}
	return context.Result(responses)
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
	Fields: []forms.Field{
		{
			Name: "rights",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsIn{Choices: []interface{}{"read", "write", "delete"}},
					},
				},
			},
		},
		{
			Name: "keys",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.Or{
							Options: [][]forms.Validator{
								[]forms.Validator{forms.IsBytes{Encoding: "base64", MaxLength: 200, MinLength: 32}},
								[]forms.Validator{forms.IsIn{Choices: []interface{}{""}}},
							},
						},
					},
				},
			},
		},
	},
}

var GrantContextForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "signedTokenData",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{
					Form: &SignedTokenDataForm,
				},
			},
		},
	},
}

var GrantForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &GrantDataForm,
				},
			},
		},
		{
			Name: "context",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{
					Form: &GrantContextForm,
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

var GrantDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "objectID",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "grantID",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "singleUse",
			Validators: []forms.Validator{
				forms.IsOptional{Default: true},
				forms.IsBoolean{},
			},
		},
		{
			Name: "type",
			Validators: []forms.Validator{
				forms.IsOptional{Default: "default"},
				forms.IsIn{Choices: []interface{}{"default", "token"}},
			},
		},
		{
			Name: "expiresAt",
			Validators: []forms.Validator{
				forms.IsTime{
					Format: "rfc3339",
				},
			},
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
	},
}

type StoreDataParams struct {
	JSON      string         `json:"json"`
	Data      *StoreDataData `json:"data"`
	Signature []byte         `json:"signature"`
	PublicKey []byte         `json:"publicKey"`
}

type Permissions struct {
	Permissions []*Permission
}

func (c *Appointments) verifyGrant(context *jsonrpc.Context, transaction services.Transaction, id []byte, rights []string, publicKey []byte, grant *Grant) *jsonrpc.Response {

	notAuthorized := context.Error(401, "not authorized", nil)
	permissionObj := transaction.Value("permissions", id)
	value, err := permissionObj.Get()

	if err != nil {
		if err != databases.NotFound {
			return context.InternalError()
		}
	} else if len(value) > 0 {
		// grants can't be applied to objects that already have permissions...
		return notAuthorized
	}

	// we check that this grant is still valid
	resp, _ := c.isProvider(context, []byte(grant.JSON), grant.Signature, grant.PublicKey)
	if resp != nil {
		return resp
	}

	if !bytes.Equal(grant.Data.ObjectID, id) {
		// not the right object ID
		return notAuthorized
	}

	if time.Now().After(grant.Data.ExpiresAt) {
		// grant is already expired
		return notAuthorized
	}

	// this is a token-based grant
	if grant.Data.Type == "token" {

		tokenKey := c.settings.Key("token")
		if tokenKey == nil {
			services.Log.Error("token key missing")
			return context.InternalError()
		}

		signedData := &crypto.SignedStringData{
			Data:      grant.Context.SignedTokenData.JSON,
			Signature: grant.Context.SignedTokenData.Signature,
		}

		// we make sure this is a valid token
		if ok, err := tokenKey.VerifyString(signedData); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else if !ok {
			return notAuthorized
		}

		token := grant.Context.SignedTokenData.Data.Token

		// we check whether the token has already been used
		grantTokens := transaction.Set("grants", []byte("tokens"))
		if ok, err := grantTokens.Has(token); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else if ok {
			// this token already has been used
			return notAuthorized
		} else if err := grantTokens.Add(token); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	// we check if the grant can be used only once
	if grant.Data.SingleUse {
		grants := transaction.Set("grants", []byte("data"))
		if ok, err := grants.Has(grant.Data.GrantID); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else if ok {
			// this code has already been used
			return notAuthorized
		} else if err := grants.Add(grant.Data.GrantID); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}
	for _, permission := range grant.Data.Permissions {
		for _, pk := range permission.Keys {
			if bytes.Equal(pk, publicKey) {
				for _, requiredRight := range rights {
					found := false
					for _, right := range permission.Rights {
						if right == requiredRight {
							found = true
							break
						}
					}
					// there's a right missing
					if !found {
						return notAuthorized
					}
				}
				// this key matches and grants the necessary rights
				return nil
			}
		}
	}
	// no permission matched
	return notAuthorized
}

func (c *Appointments) verifyPermissions(context *jsonrpc.Context, transaction services.Transaction, id []byte, rights []string, publicKey []byte, isProvider bool) *jsonrpc.Response {

	notAuthorized := context.Error(401, "not authorized", nil)
	permissionObj := transaction.Value("permissions", id)
	value, err := permissionObj.Get()

	if err != nil {
		if err == databases.NotFound {
			if isProvider {
				// providers can create data
				return nil
			}
			return notAuthorized
		} else {
			return context.InternalError()
		}
	}

	if len(value) == 0 {
		return notAuthorized
	}

	// there's an existing permissions object on this data
	var permissions []*Permission
	if err := json.Unmarshal(value, &permissions); err != nil {
		services.Log.Errorf("JSON error: %v", err)
		return context.InternalError()
	}
	for _, permission := range permissions {
		for _, pk := range permission.Keys {
			if len(pk) == 0 || bytes.Equal(pk, publicKey) {
				for _, requiredRight := range rights {
					found := false
					for _, right := range permission.Rights {
						if right == requiredRight {
							found = true
							break
						}
					}
					// there's a right missing
					if !found {
						return notAuthorized
					}
				}
				// this key matches and grants the necessary rights
				return nil
			}
		}
	}
	// no permission matched
	return notAuthorized
}

func (c *Appointments) setPermissions(context *jsonrpc.Context, transaction services.Transaction, id []byte, permissions []*Permission, publicKey []byte, ttl time.Duration) *jsonrpc.Response {

	permissionObj := transaction.Value("permissions", id)

	for _, permission := range permissions {
		newKeys := [][]byte{}
		for _, key := range permission.Keys {
			if len(key) == 0 {
				// if this is a wildcard permission object we apply the provided publicKey
				newKeys = append(newKeys, publicKey)
			} else {
				newKeys = append(newKeys, key)
			}
		}
		permission.Keys = newKeys
	}

	if permissionsBytes, err := json.Marshal(permissions); err != nil {
		return context.InternalError()
	} else if err := permissionObj.Set(permissionsBytes, ttl); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if result, err := permissionObj.Get(); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !bytes.Equal(result, permissionsBytes) {
		return context.InternalError()
	}

	return nil
}

func (c *Appointments) storeDataHelper(context *jsonrpc.Context, jsonData string, publicKey, signature []byte, data *StoreDataData) *jsonrpc.Response {

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	ttl := time.Hour * 24 * time.Duration(c.settings.DataTTLDays)
	value := transaction.Value("data", data.ID)

	isProvider := false

	// we check if this is a valid provider
	resp, _ := c.isProvider(context, []byte(jsonData), signature, publicKey)

	if resp == nil {
		isProvider = true
	}

	if err == databases.NotFound {
		return context.NotFound()
	}

	// only providers can directly write data to the backend
	if !isProvider {
		// we check if there's a grant included with the request
		if data.Grant != nil {
			// we check if the grant is still valid
			if result := c.verifyGrant(context, transaction, data.ID, []string{"write"}, publicKey, data.Grant); result != nil {
				return result
			} else if result := c.setPermissions(context, transaction, data.ID, data.Grant.Data.Permissions, publicKey, ttl); result != nil {
				return result
			}
		} else if result := c.verifyPermissions(context, transaction, data.ID, []string{"write"}, publicKey, false); result != nil {
			return result
		}
	} else {
		if result := c.verifyPermissions(context, transaction, data.ID, []string{"write"}, publicKey, true); result != nil {
			return result
		}
		if result := c.setPermissions(context, transaction, data.ID, data.Permissions, publicKey, ttl); result != nil {
			return result
		}
	}

	if dv, err := json.Marshal(data.Data); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if err := value.Set(dv, ttl); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		success = true
		return nil
	}
}

// { id, data, permissions, grant }, keyPair
// store provider data for verification
func (c *Appointments) storeData(context *jsonrpc.Context, params *StoreDataParams) *jsonrpc.Response {

	// we verify the signature (without veryfing e.g. the provenance of the key)
	if ok, err := crypto.VerifyWithBytes([]byte(params.JSON), params.Signature, params.PublicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	if result := c.storeDataHelper(context, params.JSON, params.PublicKey, params.Signature, params.Data); result != nil {
		return result
	}
	return context.Acknowledge()
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
		{
			Name: "queueData",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &TokenQueueDataForm,
				},
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

var TokenQueueDataForm = forms.Form{
	Fields: []forms.Field{
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
			Name: "distance",
			Validators: []forms.Validator{
				forms.IsOptional{Default: 5},
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    5,
					Max:    50,
				},
			},
		},
		{
			Name: "accessible",
			Validators: []forms.Validator{
				forms.IsOptional{Default: false},
				forms.IsBoolean{},
			},
		},
		{
			Name: "offerReceived",
			Validators: []forms.Validator{
				forms.IsOptional{Default: false},
				forms.IsBoolean{},
			},
		},
		{
			Name: "offerAccepted",
			Validators: []forms.Validator{
				forms.IsOptional{Default: false},
				forms.IsBoolean{},
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
	Hash      []byte `json:"hash"`
	Code      []byte `json:"code"`
	PublicKey []byte `json:"publicKey"`
}

type SignedTokenData struct {
	JSON      string     `json:"json"`
	Data      *TokenData `json:"data"`
	Signature []byte     `json:"signature"`
	PublicKey []byte     `json:"publicKey"`
}

type TokenData struct {
	PublicKey []byte `json:"publicKey"`
	Token     []byte `json:"token"`
	Hash      []byte `json:"hash"`
}

//{hash, encryptedData, queueID, queueData, signedTokenData}
// get a token for a given queue
func (c *Appointments) getToken(context *jsonrpc.Context, params *GetTokenParams) *jsonrpc.Response {

	codes := c.db.Set("codes", []byte("user"))
	codeScores := c.db.SortedSet("codeScores", []byte("user"))

	tokenKey := c.settings.Key("token")
	if tokenKey == nil {
		services.Log.Error("token key missing")
		return context.InternalError()
	}

	var signedData *crypto.SignedStringData

	// this is a new token
	if c.settings.UserCodesEnabled {
		notAuthorized := context.Error(401, "not authorized", nil)
		if params.Code == nil {
			return notAuthorized
		}
		if ok, err := codes.Has(params.Code); err != nil {
			services.Log.Error()
			return context.InternalError()
		} else if !ok {
			return notAuthorized
		}
	}

	if _, token, err := c.priorityToken(); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else {
		tokenData := &TokenData{
			Hash:      params.Hash,
			Token:     token,
			PublicKey: params.PublicKey,
		}

		td, err := json.Marshal(tokenData)

		if err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}

		if signedData, err = tokenKey.SignString(string(td)); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	// if this is a new token we delete the user code
	if c.settings.UserCodesEnabled {
		score, err := codeScores.Score(params.Code)
		if err != nil && err != databases.NotFound {
			services.Log.Error(err)
			return context.InternalError()
		}

		score += 1

		if score > c.settings.UserCodesReuseLimit {
			if err := codes.Del(params.Code); err != nil {
				services.Log.Error(err)
				return context.InternalError()
			}
		} else if err := codeScores.Add(params.Code, score); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	return context.Result(signedData)

}

// provider-only endpoints

var tws = []services.TimeWindowFunc{
	services.Minute,
	services.QuarterHour,
	services.Hour,
	services.Day,
	services.Week,
	services.Month,
}

var GetAppointmentsByZipCodeForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "radius",
			Validators: []forms.Validator{
				forms.IsOptional{Default: 50},
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    5,
					Max:    80,
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
	},
}

type GetAppointmentsByZipCodeParams struct {
	ZipCode string `json:"zipCode"`
	Radius  int64  `json:"radius"`
}

type ProviderAppointments struct {
	Provider *SignedProviderData  `json:"provider"`
	Offers   []*SignedAppointment `json:"offers"`
	Booked   [][]byte             `json:"booked"`
}

type SignedProviderData struct {
	ID        []byte        `json:"id"`
	JSON      string        `json:"data" coerce:"name:json"`
	Data      *ProviderData `json:"-" coerce:"name:data"`
	Signature []byte        `json:"signature"`
	PublicKey []byte        `json:"publicKey"`
}

type ProviderData struct {
	Name        string `json:"name"`
	Street      string `json:"street"`
	City        string `json:"city"`
	ZipCode     string `json:"zipCode"`
	Description string `json:"description"`
}

/*
- Get all neighbors of the given zip code within the given radius
*/
func (c *Appointments) getAppointmentsByZipCode(context *jsonrpc.Context, params *GetAppointmentsByZipCodeParams) *jsonrpc.Response {

	keys, err := c.getKeysData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	neighbors := c.db.SortedSet("distances::neighbors::zipCode", []byte(params.ZipCode))
	publicProviderData := c.db.Map("providerData", []byte("public"))

	allNeighbors, err := neighbors.Range(0, -1)
	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	distances := map[string]int64{}

	for _, neighbor := range allNeighbors {
		distances[string(neighbor.Data)] = neighbor.Score
	}

	providerAppointmentsList := []*ProviderAppointments{}

	for _, providerKey := range keys.Lists.Providers {
		pkd, err := providerKey.ProviderKeyData()
		if err != nil {
			services.Log.Error(err)
			continue
		}

		if pkd.QueueData.ZipCode != params.ZipCode {
			if distance, ok := distances[pkd.QueueData.ZipCode]; !ok {
				continue
			} else if distance > params.Radius {
				continue
			}
		}

		// the provider "ID" is the hash of the signing key
		hash := crypto.Hash(pkd.Signing)

		pd, err := publicProviderData.Get(hash)

		if err != nil {
			if err != databases.NotFound {
				services.Log.Error(err)
			}
			services.Log.Info("provider data not found")
			continue
		}

		providerData := &SignedProviderData{}
		var providerDataMap map[string]interface{}

		if err := json.Unmarshal(pd, &providerDataMap); err != nil {
			services.Log.Error(err)
			continue
		}

		if params, err := SignedProviderDataForm.Validate(providerDataMap); err != nil {
			services.Log.Error(err)
			continue
		} else if err := SignedProviderDataForm.Coerce(providerData, params); err != nil {
			services.Log.Error(err)
			continue
		}

		providerData.ID = hash

		bookings := c.db.Map("bookings", hash)

		allBookings, err := bookings.GetAll()

		if err != nil {
			services.Log.Error(err)
			continue
		}

		appointmentsMap := c.db.Map("appointments", hash)
		allAppointments, err := appointmentsMap.GetAll()

		if err != nil {
			services.Log.Error(err)
		}

		appointments := []*SignedAppointment{}

		for _, data := range allAppointments {
			var appointment *SignedAppointment
			if err := json.Unmarshal(data, &appointment); err != nil {
				services.Log.Error(err)
				continue
			}

			if err := json.Unmarshal([]byte(appointment.JSON), &appointment.Data); err != nil {
				continue
			}

			if appointment.JSON == "" || appointment.PublicKey == nil || appointment.Signature == nil || appointment.Data == nil || appointment.Data.Timestamp.Before(time.Now()) {
				continue
			}

			appointments = append(appointments, appointment)
		}

		if len(appointments) == 0 {
			continue
		}

		bookedSlots := [][]byte{}

		for k, _ := range allBookings {
			bookedSlots = append(bookedSlots, []byte(k))
		}

		providerAppointments := &ProviderAppointments{
			Provider: providerData,
			Offers:   appointments,
			Booked:   bookedSlots,
		}

		providerAppointmentsList = append(providerAppointmentsList, providerAppointments)

	}

	return context.Result(providerAppointmentsList)
}

var GetProviderAppointmentsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &GetProviderAppointmentsDataForm,
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

var GetProviderAppointmentsDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{Format: "rfc3339"},
			},
		},
	},
}

type GetProviderAppointmentsParams struct {
	JSON      string                       `json:"json"`
	Data      *GetProviderAppointmentsData `json:"data"`
	Signature []byte                       `json:"signature"`
	PublicKey []byte                       `json:"publicKey"`
}

type GetProviderAppointmentsData struct {
	Timestamp *time.Time `json:"timestamp"`
}

func (c *Appointments) getProviderAppointments(context *jsonrpc.Context, params *GetProviderAppointmentsParams) *jsonrpc.Response {

	// make sure this is a valid provider asking for tokens
	resp, providerKey := c.isProvider(context, []byte(params.JSON), params.Signature, params.PublicKey)

	if resp != nil {
		return resp
	}

	if expired(params.Data.Timestamp) {
		return context.Error(410, "signature expired", nil)
	}

	pkd, err := providerKey.ProviderKeyData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	// the provider "ID" is the hash of the signing key
	hash := crypto.Hash(pkd.Signing)

	// appointments are stored in a provider-specific key
	appointments := c.db.Map("appointments", hash)
	allAppointments, err := appointments.GetAll()

	signedAppointments := make([]*SignedAppointment, 0)

	for _, appointment := range allAppointments {
		var signedAppointment *SignedAppointment
		if err := json.Unmarshal(appointment, &signedAppointment); err != nil {
			services.Log.Error(err)
			continue
		}
		signedAppointments = append(signedAppointments, signedAppointment)
	}

	return context.Result(signedAppointments)
}

var PublishAppointmentsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &PublishAppointmentsDataForm,
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

var PublishAppointmentsDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{Format: "rfc3339"},
			},
		},
		{
			Name: "reset",
			Validators: []forms.Validator{
				forms.IsOptional{Default: false},
				forms.IsBoolean{},
			},
		},
		{
			Name: "offers",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &AppointmentForm,
						},
					},
				},
			},
		},
	},
}

var AppointmentPropertiesForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "vaccine",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"biontech", "moderna", "astrazeneca", "johnson-johnson"}},
			},
		},
	},
}

var AppointmentForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &AppointmentDataForm,
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

var AppointmentDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{Format: "rfc3339"},
			},
		},
		{
			Name: "duration",
			Validators: []forms.Validator{
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    5,
					Max:    300,
				},
			},
		},
		{
			Name: "properties",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &AppointmentPropertiesForm,
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
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "slotData",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &SlotForm,
						},
					},
				},
			},
		},
	},
}

var SlotForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}

type PublishAppointmentsParams struct {
	JSON      string                   `json:"json"`
	Data      *PublishAppointmentsData `json:"data"`
	Signature []byte                   `json:"signature"`
	PublicKey []byte                   `json:"publicKey"`
}

type PublishAppointmentsData struct {
	Timestamp *time.Time           `json:"timestamp"`
	Offers    []*SignedAppointment `json:"offers"`
	Reset     bool                 `json:"reset"`
}

type SignedAppointment struct {
	JSON      string       `json:"data" coerce:"name:json"`
	Data      *Appointment `json:"-" coerce:"name:data"`
	Signature []byte       `json:"signature"`
	PublicKey []byte       `json:"publicKey"`
}

type Appointment struct {
	Timestamp  time.Time              `json:"timestamp"`
	Duration   int64                  `json:"duration"`
	Properties map[string]interface{} `json:"properties"`
	SlotData   []*Slot                `json:"slotData"`
	ID         []byte                 `json:"id"`
	PublicKey  []byte                 `json:"publicKey"`
}

type Slot struct {
	ID []byte `json:"id"`
}

func (c *Appointments) publishAppointments(context *jsonrpc.Context, params *PublishAppointmentsParams) *jsonrpc.Response {

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	// make sure this is a valid provider asking for tokens
	resp, providerKey := c.isProvider(context, []byte(params.JSON), params.Signature, params.PublicKey)

	if resp != nil {
		return resp
	}

	if expired(params.Data.Timestamp) {
		return context.Error(410, "signature expired", nil)
	}

	pkd, err := providerKey.ProviderKeyData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	// the provider "ID" is the hash of the signing key
	hash := crypto.Hash(pkd.Signing)
	hexUID := hex.EncodeToString(hash)

	// appointments are stored in a provider-specific key
	appointments := transaction.Map("appointments", hash)
	allAppointments, err := appointments.GetAll()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	// appointments expire automatically after 120 days
	if err := transaction.Expire("appointments", hash, time.Hour*24*120); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	bookings := c.db.Map("bookings", hash)
	allBookings, err := bookings.GetAll()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	var bookedSlots, openSlots int64

	for _, appointment := range params.Data.Offers {
		delete(allAppointments, string(appointment.Data.ID))
		for _, slot := range appointment.Data.SlotData {
			if _, ok := allBookings[string(slot.ID)]; ok {
				bookedSlots += 1
			} else {
				openSlots += 1
			}
			delete(allBookings, string(slot.ID))
		}
		if jsonData, err := json.Marshal(appointment); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		} else if err := appointments.Set(appointment.Data.ID, jsonData); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	if params.Data.Reset {
		// we delete appointments that are not referenced in the new data
		for k, _ := range allAppointments {
			if err := appointments.Del([]byte(k)); err != nil {
				services.Log.Error(err)
				return context.InternalError()
			}
		}

		usedTokens := transaction.Set("bookings", []byte("tokens"))

		// we delete all bookings for slots that have been removed by the provider
		for k, data := range allBookings {

			existingBooking := &Booking{}

			if err := json.Unmarshal(data, &existingBooking); err != nil {
				services.Log.Error(err)
			} else if err := usedTokens.Del(existingBooking.Token); err != nil {
				services.Log.Error(err)
			}

			if err := bookings.Del([]byte(k)); err != nil {
				services.Log.Error(err)
				return context.InternalError()
			}
		}

	}

	success = true

	if c.meter != nil {

		now := time.Now().UTC().UnixNano()

		addTokenStats := func(tw services.TimeWindow, data map[string]string) error {
			// we add the maximum of the open appointments
			if err := c.meter.AddMax("queues", "open", hexUID, data, tw, openSlots); err != nil {
				return err
			}
			// we add the maximum of the booked appointments
			if err := c.meter.AddMax("queues", "booked", hexUID, data, tw, bookedSlots); err != nil {
				return err
			}
			// we add the info that this provider is active
			if err := c.meter.AddOnce("queues", "active", hexUID, data, tw, 1); err != nil {
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
				"zipCode": pkd.QueueData.ZipCode,
			}); err != nil {
				services.Log.Error(err)
			}

		}

	}

	return context.Acknowledge()
}

var GetBookedAppointmentsDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{Format: "rfc3339"},
			},
		},
	},
}
var GetBookedAppointmentsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &GetBookedAppointmentsDataForm,
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

type GetBookedAppointmentsParams struct {
	JSON      string                     `json:"json"`
	Data      *GetBookedAppointmentsData `json:"data"`
	Signature []byte                     `json:"signature"`
	PublicKey []byte                     `json:"publicKey"`
}

type GetBookedAppointmentsData struct {
	Timestamp *time.Time `json:"timestamp"`
}

func (c *Appointments) getBookedAppointments(context *jsonrpc.Context, params *GetBookedAppointmentsParams) *jsonrpc.Response {

	// make sure this is a valid provider asking for tokens
	resp, providerKey := c.isProvider(context, []byte(params.JSON), params.Signature, params.PublicKey)

	if resp != nil {
		return resp
	}

	if expired(params.Data.Timestamp) {
		return context.Error(410, "signature expired", nil)
	}

	pkd, err := providerKey.ProviderKeyData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	// the provider "ID" is the hash of the signing key
	hash := crypto.Hash(pkd.Signing)

	bookings := c.db.Map("bookings", hash)

	allBookings, err := bookings.GetAll()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	bookingsList := []*Booking{}

	for _, v := range allBookings {
		var booking *Booking
		if err := json.Unmarshal(v, &booking); err != nil {
			services.Log.Error(err)
			continue
		}
		bookingsList = append(bookingsList, booking)
	}

	return context.Result(bookingsList)
}

var CancelBookingDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{Format: "rfc3339"},
			},
		},
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}
var CancelBookingForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &CancelBookingDataForm,
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

type CancelBookingParams struct {
	JSON      string             `json:"json"`
	Data      *CancelBookingData `json:"data"`
	Signature []byte             `json:"signature"`
	PublicKey []byte             `json:"publicKey"`
}

type CancelBookingData struct {
	Timestamp *time.Time `json:"timestamp"`
	ID        []byte     `json:"id"`
}

func (c *Appointments) cancelBooking(context *jsonrpc.Context, params *CancelBookingParams) *jsonrpc.Response {

	// make sure this is a valid provider asking for tokens
	resp, providerKey := c.isProvider(context, []byte(params.JSON), params.Signature, params.PublicKey)

	if resp != nil {
		return resp
	}

	if expired(params.Data.Timestamp) {
		return context.Error(410, "signature expired", nil)
	}

	pkd, err := providerKey.ProviderKeyData()

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	// the provider "ID" is the hash of the signing key
	hash := crypto.Hash(pkd.Signing)

	bookings := c.db.Map("bookings", hash)

	if err := bookings.Del(params.Data.ID); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	return context.Acknowledge()

}

var BookSlotForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &BookSlotDataForm,
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

var BookSlotDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "providerID",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "timestamp",
			Validators: []forms.Validator{
				forms.IsTime{
					Format: "rfc3339",
				},
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
					Form: &kbForms.ECDHEncryptedDataForm,
				},
			},
		},
	},
}

type BookSlotParams struct {
	JSON      string        `json:"json"`
	Data      *BookSlotData `json:"data"`
	Signature []byte        `json:"signature"`
	PublicKey []byte        `json:"publicKey"`
}

type BookSlotData struct {
	ProviderID      []byte                      `json:"providerID"`
	ID              []byte                      `json:"id"`
	EncryptedData   *services.ECDHEncryptedData `json:"encryptedData"`
	SignedTokenData *SignedTokenData            `json:"signedTokenData"`
	Timestamp       *time.Time                  `json:"timestamp"`
}

type Booking struct {
	ID            []byte                      `json:"id"`
	PublicKey     []byte                      `json:"publicKey"`
	Token         []byte                      `json:"token"`
	EncryptedData *services.ECDHEncryptedData `json:"encryptedData"`
}

func (c *Appointments) bookSlot(context *jsonrpc.Context, params *BookSlotParams) *jsonrpc.Response {

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	usedTokens := transaction.Set("bookings", []byte("tokens"))

	notAuthorized := context.Error(401, "not authorized", nil)

	signedData := &crypto.SignedStringData{
		Data:      params.Data.SignedTokenData.JSON,
		Signature: params.Data.SignedTokenData.Signature,
	}

	tokenKey := c.settings.Key("token")

	if ok, err := tokenKey.VerifyString(signedData); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	token := params.Data.SignedTokenData.Data.Token

	if ok, err := usedTokens.Has(token); err != nil {
		services.Log.Error()
		return context.InternalError()
	} else if ok {
		return notAuthorized
	}

	// we verify the signature (without veryfing e.g. the provenance of the key)
	if ok, err := crypto.VerifyWithBytes([]byte(params.JSON), params.Signature, params.PublicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	appointmentsMap := c.db.Map("appointments", params.Data.ProviderID)
	allAppointments, err := appointmentsMap.GetAll()

	if err != nil {
		services.Log.Error(err)
	}

	appointments := []*SignedAppointment{}

	for _, data := range allAppointments {
		var appointment *SignedAppointment
		if err := json.Unmarshal(data, &appointment); err != nil {
			services.Log.Error(err)
			continue
		}
		if err := json.Unmarshal([]byte(appointment.JSON), &appointment.Data); err != nil {
			services.Log.Error(err)
			continue
		}
		appointments = append(appointments, appointment)
	}

	var appointment *Appointment

	// we find the right appointment
findAppointment:
	for _, appt := range appointments {
		for _, slot := range appt.Data.SlotData {
			if bytes.Equal(slot.ID, params.Data.ID) {
				appointment = appt.Data
				break findAppointment
			}
		}
	}

	if appointment == nil {
		return context.NotFound()
	}

	bookings := transaction.Map("bookings", params.Data.ProviderID)

	// appointments expire automatically after 120 days
	if err := transaction.Expire("bookings", params.Data.ProviderID, time.Hour*24*120); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	existingBooking := &Booking{}

	if existingBookingData, err := bookings.Get(params.Data.ID); err != nil {
		if err != databases.NotFound {
			services.Log.Error(err)
			return context.InternalError()
		}
	} else if err := json.Unmarshal(existingBookingData, &existingBooking); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !bytes.Equal(existingBooking.PublicKey, params.PublicKey) {
		// the public key does not match
		return context.Error(401, "permission denied", nil)
	}

	booking := &Booking{
		PublicKey:     params.PublicKey,
		ID:            params.Data.ID,
		Token:         token,
		EncryptedData: params.Data.EncryptedData,
	}

	if data, err := json.Marshal(booking); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if err := bookings.Set(params.Data.ID, data); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	if err := usedTokens.Add(token); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	if c.meter != nil {

		now := time.Now().UTC().UnixNano()

		for _, twt := range tws {

			// generate the time window
			tw := twt(now)

			// we add the info that a booking was made
			if err := c.meter.Add("queues", "bookings", map[string]string{}, tw, 1); err != nil {
				services.Log.Error(err)
			}

		}

	}

	return context.Acknowledge()

}

var CancelSlotForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "data",
			Validators: []forms.Validator{
				forms.IsString{},
				JSON{
					Key: "json",
				},
				forms.IsStringMap{
					Form: &CancelSlotDataForm,
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

var CancelSlotDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
		{
			Name: "providerID",
			Validators: []forms.Validator{
				ID,
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
	},
}

type CancelSlotParams struct {
	JSON      string          `json:"json"`
	Data      *CancelSlotData `json:"data"`
	Signature []byte          `json:"signature"`
	PublicKey []byte          `json:"publicKey"`
}

type CancelSlotData struct {
	ProviderID      []byte           `json:"providerID"`
	SignedTokenData *SignedTokenData `json:"signedTokenData"`
	ID              []byte           `json:"id"`
}

func (c *Appointments) cancelSlot(context *jsonrpc.Context, params *CancelSlotParams) *jsonrpc.Response {
	// we verify the signature (without veryfing e.g. the provenance of the key)
	if ok, err := crypto.VerifyWithBytes([]byte(params.JSON), params.Signature, params.PublicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	bookings := transaction.Map("bookings", params.Data.ProviderID)

	existingBooking := &Booking{}

	if existingBookingData, err := bookings.Get(params.Data.ID); err != nil {
		if err == databases.NotFound {
			return context.NotFound()
		}
		services.Log.Error(err)
		return context.InternalError()
	} else if err := json.Unmarshal(existingBookingData, &existingBooking); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !bytes.Equal(existingBooking.PublicKey, params.PublicKey) {
		// the public key does not match
		return context.Error(401, "permission denied", nil)
	}

	if err := bookings.Del(params.Data.ID); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	// we reenabe the token

	usedTokens := transaction.Set("bookings", []byte("tokens"))

	signedData := &crypto.SignedStringData{
		Data:      params.Data.SignedTokenData.JSON,
		Signature: params.Data.SignedTokenData.Signature,
	}

	tokenKey := c.settings.Key("token")

	if ok, err := tokenKey.VerifyString(signedData); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	token := params.Data.SignedTokenData.Data.Token

	if ok, err := usedTokens.Has(token); err != nil {
		services.Log.Error()
		return context.InternalError()
	} else if !ok {
		return context.Error(401, "not authorized", nil)
	}

	if err := usedTokens.Del(token); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	if c.meter != nil {

		now := time.Now().UTC().UnixNano()

		for _, twt := range tws {

			// generate the time window
			tw := twt(now)

			// we add the info that a booking was made
			if err := c.meter.Add("queues", "cancellations", map[string]string{}, tw, 1); err != nil {
				services.Log.Error(err)
			}

		}

	}

	return context.Acknowledge()

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

func (c *Appointments) transaction(success *bool) (services.Transaction, func(), error) {
	transaction, err := c.db.Begin()

	if err != nil {
		return nil, nil, err
	}

	finalize := func() {
		if *success {
			if err := transaction.Commit(); err != nil {
				services.Log.Error(err)
			}
		} else {
			if err := transaction.Rollback(); err != nil {
				services.Log.Error(err)
			}
		}
	}

	return transaction, finalize, nil

}

// { id, encryptedData, code }, keyPair
func (c *Appointments) storeProviderData(context *jsonrpc.Context, params *StoreProviderDataParams) *jsonrpc.Response {

	success := false
	transaction, finalize, err := c.transaction(&success)

	if err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	defer finalize()

	verifiedProviderData := transaction.Map("providerData", []byte("verified"))
	providerData := transaction.Map("providerData", []byte("unverified"))
	codes := transaction.Set("codes", []byte("provider"))
	codeScores := c.db.SortedSet("codeScores", []byte("provider"))

	existingData := false
	if result, err := verifiedProviderData.Get(params.Data.ID); err != nil {
		if err != databases.NotFound {
			services.Log.Error(err)
			return context.InternalError()
		}
	} else if result != nil {
		existingData = true
	}

	providerID := append([]byte("providerData::"), params.Data.ID...)

	// we verify the signature (without veryfing e.g. the provenance of the key)
	if ok, err := crypto.VerifyWithBytes([]byte(params.JSON), params.Signature, params.PublicKey); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	} else if !ok {
		return context.Error(400, "invalid signature", nil)
	}

	if existingData {
		if result := c.verifyPermissions(context, transaction, providerID, []string{"write"}, params.PublicKey, true); result != nil {
			return result
		}
	} else if c.settings.ProviderCodesEnabled {
		notAuthorized := context.Error(401, "not authorized", nil)
		if params.Data.Code == nil {
			return notAuthorized
		}
		if ok, err := codes.Has(params.Data.Code); err != nil {
			services.Log.Error()
			return context.InternalError()
		} else if !ok {
			return notAuthorized
		}
	}

	if err := providerData.Set(params.Data.ID, []byte(params.JSON)); err != nil {
		services.Log.Error(err)
		return context.InternalError()
	}

	permissions := []*Permission{
		&Permission{
			Rights: []string{"write", "delete"},
			Keys:   [][]byte{params.PublicKey},
		},
	}

	// we give the provider the right to write and delete this data again
	if result := c.setPermissions(context, transaction, providerID, permissions, params.PublicKey, 0); result != nil {
		return result
	}

	// we delete the provider code
	if c.settings.ProviderCodesEnabled {
		score, err := codeScores.Score(params.Data.Code)
		if err != nil && err != databases.NotFound {
			services.Log.Error(err)
			return context.InternalError()
		}

		score += 1

		if score > c.settings.ProviderCodesReuseLimit {
			if err := codes.Del(params.Data.Code); err != nil {
				services.Log.Error(err)
				return context.InternalError()
			}
		} else if err := codeScores.Add(params.Data.Code, score); err != nil {
			services.Log.Error(err)
			return context.InternalError()
		}
	}

	success = true

	return context.Acknowledge()
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
				forms.IsOptional{Default: 1000},
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    1,
					Max:    10000,
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

var GetVerifiedProviderDataForm = forms.Form{
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

var GetVerifiedProviderDataDataForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "limit",
			Validators: []forms.Validator{
				forms.IsOptional{Default: 1000},
				forms.IsInteger{
					HasMin: true,
					HasMax: true,
					Min:    1,
					Max:    10000,
				},
			},
		},
	},
}

type GetVerifiedProviderDataParams struct {
	JSON      string                       `json:"json"`
	Data      *GetVerifiedProviderDataData `json:"data"`
	Signature []byte                       `json:"signature"`
	PublicKey []byte                       `json:"publicKey"`
}

type GetVerifiedProviderDataData struct {
	N int64 `json:"n"`
}

// mediator-only endpoint
// { limit }, keyPair
func (c *Appointments) getVerifiedProviderData(context *jsonrpc.Context, params *GetVerifiedProviderDataParams) *jsonrpc.Response {

	if resp, _ := c.isMediator(context, []byte(params.JSON), params.Signature, params.PublicKey); resp != nil {
		return resp
	}

	providerData := c.db.Map("providerData", []byte("verified"))

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
				forms.IsIn{Choices: []interface{}{"queues", "tokens"}},
			},
		},
		{
			Name: "type",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"minute", "hour", "day", "quarterHour", "week", "month"}},
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
			Name: "metric",
			Validators: []forms.Validator{
				forms.IsOptional{Default: ""},
				forms.MatchesRegex{Regex: regexp.MustCompile(`^[\w\d\-]{0,50}$`)},
			},
		},
		{
			Name: "filter",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{},
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
	ID     string                 `json:"id"`
	Type   string                 `json:"type"`
	Filter map[string]interface{} `json:"filter"`
	Metric string                 `json:"metric"`
	Name   string                 `json:"name"`
	From   *time.Time             `json:"from"`
	To     *time.Time             `json:"to"`
	N      *int64                 `json:"n"`
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

addMetric:
	for _, metric := range metrics {
		if params.Metric != "" && metric.Name != params.Metric {
			continue
		}
		if metric.Name[0] == '_' {
			// we skip internal metrics (which start with a '_')
			continue
		}

		if params.Filter != nil {
			for k, v := range params.Filter {
				// if v is nil we only return metrics without a value for the given key
				if v == nil {
					if _, ok := metric.Data[k]; ok {
						continue addMetric
					}
				} else if dv, ok := metric.Data[k]; !ok || dv != v {
					// filter value is missing or does not match
					continue addMetric
				}
			}
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
