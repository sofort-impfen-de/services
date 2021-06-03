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

package helpers

import (
	"encoding/json"
	"github.com/kiebitz-oss/services"
	kbForms "github.com/kiebitz-oss/services/forms"
	"github.com/kiebitz-oss/services/jsonrpc"
	"github.com/kiprotect/go-helpers/forms"
	"github.com/urfave/cli"
	"io/ioutil"
	"time"
)

var QueuesForm = forms.Form{
	Fields: []forms.Field{
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

type Queues struct {
	Queues []*services.Queue `json:"queues"`
}

func uploadQueueData(settings *services.Settings) func(c *cli.Context) error {
	return func(c *cli.Context) error {

		if settings.Admin == nil {
			services.Log.Fatal("admin settings missing")
		}

		filename := c.Args().Get(0)

		if filename == "" {
			services.Log.Fatal("please specify a filename")
		}

		jsonBytes, err := ioutil.ReadFile(filename)

		if err != nil {
			services.Log.Fatal(err)
		}

		queues := &Queues{}
		var rawQueues map[string]interface{}

		if err := json.Unmarshal(jsonBytes, &rawQueues); err != nil {
			services.Log.Fatal(err)
		}

		if params, err := QueuesForm.Validate(rawQueues); err != nil {
			services.Log.Fatal(err)
		} else if QueuesForm.Coerce(queues, params); err != nil {
			services.Log.Fatal(err)
		}

		client := jsonrpc.MakeClient(settings.Admin.Client.AppointmentsEndpoint)

		data := map[string]interface{}{
			"queues":    queues.Queues,
			"timestamp": time.Now(),
		}

		signingKey := settings.Admin.Signing.Key("root")

		if signingKey == nil {
			services.Log.Fatal("can't find signing key")
		}

		bytes, err := json.Marshal(data)

		if err != nil {
			services.Log.Fatal(err)
		}

		signedData, err := signingKey.SignString(string(bytes))

		if err != nil {
			services.Log.Fatal(err)
		}

		request := jsonrpc.MakeRequest("setQueues", "", signedData.AsMap())

		if response, err := client.Call(request); err != nil {
			services.Log.Fatal(err)
		} else {
			services.Log.Info(response.AsJSON())
		}

		return nil
	}
}

var KeyPairsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "signing",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &KeyPairForm,
				},
			},
		},
		{
			Name: "encryption",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &KeyPairForm,
				},
			},
		},
	},
}

var KeyPairForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "publicKey",
			Validators: []forms.Validator{
				forms.IsBytes{
					Encoding: "base64",
				},
			},
		},
		{
			Name: "privateKey",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &JWKPrivateKeyForm,
				},
			},
		},
	},
}

var JWKPrivateKeyForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "crv",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "d",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "x",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "y",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "ext",
			Validators: []forms.Validator{
				forms.IsBoolean{},
			},
		},
		{
			Name: "key_ops",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsString{},
					},
				},
			},
		},
		{
			Name: "kty",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
	},
}

type KeyPairs struct {
	Signing    *KeyPair `json:"signing"`
	Encryption *KeyPair `json:"encryption"`
}

type KeyPair struct {
	PublicKey  []byte         `json:"publicKey"`
	PrivateKey *JWKPrivateKey `json:"privateKey"`
}

type JWKPrivateKey struct {
	Curve  string   `json:"crv"`
	D      string   `json:"d"`
	Ext    bool     `json:"ext"`
	KeyOps []string `json:"key_ops"`
	Kty    string   `json:"kty"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

func uploadMediatorKeys(settings *services.Settings) func(c *cli.Context) error {
	return func(c *cli.Context) error {

		if settings.Admin == nil {
			services.Log.Fatal("admin settings missing")
		}

		filename := c.Args().Get(0)

		if filename == "" {
			services.Log.Fatal("please specify a filename")
		}

		jsonBytes, err := ioutil.ReadFile(filename)

		if err != nil {
			services.Log.Fatal(err)
		}

		keyPairs := &KeyPairs{}
		var rawKeyPairs map[string]interface{}

		if err := json.Unmarshal(jsonBytes, &rawKeyPairs); err != nil {
			services.Log.Fatal(err)
		}

		if params, err := KeyPairsForm.Validate(rawKeyPairs); err != nil {
			services.Log.Fatal(err)
		} else if KeyPairsForm.Coerce(keyPairs, params); err != nil {
			services.Log.Fatal(err)
		}

		client := jsonrpc.MakeClient(settings.Admin.Client.AppointmentsEndpoint)

		data := map[string]interface{}{
			"signing":    keyPairs.Signing.PublicKey,
			"encryption": keyPairs.Encryption.PublicKey,
			"timestamp":  time.Now(),
		}

		signingKey := settings.Admin.Signing.Key("root")

		if signingKey == nil {
			services.Log.Fatal("can't find signing key")
		}

		bytes, err := json.Marshal(data)

		if err != nil {
			services.Log.Fatal(err)
		}

		signedData, err := signingKey.SignString(string(bytes))

		if err != nil {
			services.Log.Fatal(err)
		}

		request := jsonrpc.MakeRequest("addMediatorPublicKeys", "", signedData.AsMap())

		if response, err := client.Call(request); err != nil {
			services.Log.Fatal(err)
		} else {
			services.Log.Info(response.AsJSON())
		}

		return nil
	}
}

func Admin(settings *services.Settings) ([]cli.Command, error) {

	return []cli.Command{
		{
			Name:    "admin",
			Aliases: []string{"a"},
			Flags:   []cli.Flag{},
			Usage:   "Administrative functions.",
			Subcommands: []cli.Command{
				{
					Name:  "queues",
					Flags: []cli.Flag{},
					Usage: "Queues-related command.",
					Subcommands: []cli.Command{
						{
							Name:   "upload",
							Flags:  []cli.Flag{},
							Usage:  "upload queue data from a file to the backend",
							Action: uploadQueueData(settings),
						},
					},
				},
				{
					Name:  "mediators",
					Flags: []cli.Flag{},
					Usage: "Mediators-related command.",
					Subcommands: []cli.Command{
						{
							Name:   "upload-keys",
							Flags:  []cli.Flag{},
							Usage:  "upload signed keys data for a mediator",
							Action: uploadMediatorKeys(settings),
						},
					},
				},
			},
		},
	}, nil
}
