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
	"github.com/kiebitz-oss/services"
	"github.com/kiebitz-oss/services/databases"
	"github.com/kiebitz-oss/services/jsonrpc"
	"github.com/kiprotect/go-helpers/forms"
	"time"
)

type Storage struct {
	settings *services.StorageSettings
	server   *jsonrpc.JSONRPCServer
	db       services.Database
}

func MakeStorage(settings *services.StorageSettings, db services.Database) (*Storage, error) {

	Storage := &Storage{
		db:       db,
		settings: settings,
	}

	methods := map[string]*jsonrpc.Method{
		"storeSettings": {
			Form:    &StoreSettingsForm,
			Handler: Storage.storeSettings,
		},
		"getSettings": {
			Form:    &GetSettingsForm,
			Handler: Storage.getSettings,
		},
		"deleteSettings": {
			Form:    &DeleteSettingsForm,
			Handler: Storage.deleteSettings,
		},
	}

	handler, err := jsonrpc.MethodsHandler(methods)

	if err != nil {
		return nil, err
	}

	if jsonrpcServer, err := jsonrpc.MakeJSONRPCServer(settings.RPC, handler); err != nil {
		return nil, err
	} else {
		Storage.server = jsonrpcServer
		return Storage, nil
	}
}

var StoreSettingsForm = forms.Form{
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
				forms.IsBytes{
					Encoding:  "base64",
					MinLength: 1,
					MaxLength: 1024 * 8, // max 8kB
				},
			},
		},
	},
}

type StoreSettingsParams struct {
	ID   []byte `json:"id"`
	Data []byte `json:"data"`
}

// store the settings in the database by ID
func (c *Storage) storeSettings(context *jsonrpc.Context, params *StoreSettingsParams) *jsonrpc.Response {
	value := c.db.Value("settings", params.ID)
	if err := value.Set(params.Data, time.Duration(c.settings.SettingsTTLDays*24)*time.Hour); err != nil {
		return context.InternalError()
	}
	if err := value.Save(); err != nil {
		return context.InternalError()
	}
	return context.Acknowledge()
}

type GetSettingsParams struct {
	ID []byte `json:"id"`
}

var GetSettingsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}

func (c *Storage) getSettings(context *jsonrpc.Context, params *GetSettingsParams) *jsonrpc.Response {
	value := c.db.Value("settings", params.ID)
	if data, err := value.Get(); err != nil {
		if err == databases.NotFound {
			return context.NotFound()
		} else {
			services.Log.Error(err)
			return context.InternalError()
		}
	} else {
		return context.Result(Encode(data))
	}
}

type DeleteSettingsParams struct {
	ID []byte `json:"id"`
}

var DeleteSettingsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "id",
			Validators: []forms.Validator{
				ID,
			},
		},
	},
}

func (c *Storage) deleteSettings(context *jsonrpc.Context, params *GetSettingsParams) *jsonrpc.Response {
	return context.InternalError()
}

func (c *Storage) Start() error {
	return c.server.Start()
}

func (c *Storage) Stop() error {
	return c.server.Stop()
}
