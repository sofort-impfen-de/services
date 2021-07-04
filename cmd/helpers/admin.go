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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/kiebitz-oss/services"
	"github.com/kiebitz-oss/services/crypto"
	kbForms "github.com/kiebitz-oss/services/forms"
	"github.com/kiebitz-oss/services/helpers"
	"github.com/kiebitz-oss/services/jsonrpc"
	"github.com/kiprotect/go-helpers/forms"
	"github.com/urfave/cli"
	"io/ioutil"
	"time"
)

var UploadDistancesForm = forms.Form{
	Fields: []forms.Field{
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
				forms.IsFloat{HasMin: true, Min: 0.0, HasMax: true, Max: 200.0},
			},
		},
	},
}

type UploadDistances struct {
	Type      string      `json:"type"`
	Distances []*Distance `json:"distances"`
	Timestamp *time.Time  `json:"timestamp"`
}

type Distance struct {
	From     string  `json:"from"`
	To       string  `json:"to"`
	Distance float64 `json:"distance"`
}

func generateMediatorKeys(settings *services.Settings) func(c *cli.Context) error {
	return func(c *cli.Context) error {

		keys := map[string]string{
			"signing":    "ecdsa",
			"encryption": "ecdh",
		}

		keyData := map[string]interface{}{}

		for name, keyType := range keys {
			queueDataKey, err := crypto.GenerateKey()

			if err != nil {
				services.Log.Fatal(err)
			}

			webKey, err := crypto.AsWebKey(queueDataKey, keyType)

			if err != nil {
				services.Log.Fatal(err)
			}

			keyData[name] = webKey

		}

		for _, name := range []string{"queue", "provider"} {
			key := settings.Admin.Signing.Key(name)
			publicKey, err := crypto.LoadPublicKey(key.PublicKey)
			if err != nil {
				services.Log.Fatal(err)
			}

			privateKey, err := crypto.LoadPrivateKey(key.PrivateKey)
			if err != nil {
				services.Log.Fatal(err)
			}

			privateKey.PublicKey = *publicKey

			webKey, err := crypto.AsWebKey(privateKey, key.Type)

			if err != nil {
				services.Log.Fatal(err)
			}

			keyData[name] = webKey
		}

		jsonData, err := json.MarshalIndent(keyData, "", "  ")

		if err != nil {
			services.Log.Fatal(err)
		}

		fmt.Println(string(jsonData))

		return nil
	}
}

var queueAreas = []string{"01", "02", "03", "04", "06", "07", "08", "09", "10", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99"}

func generateQueues(settings *services.Settings) func(c *cli.Context) error {

	return func(c *cli.Context) error {

		queues := []*services.Queue{}

		queueEncryptionKey := settings.Admin.Signing.Key("queue")
		queueEncryptionPublicKey, err := crypto.LoadPublicKey(queueEncryptionKey.PublicKey)
		if err != nil {
			services.Log.Fatal(err)
		}

		for _, area := range queueAreas {

			ephemeralKey, err := crypto.GenerateKey()

			if err != nil {
				services.Log.Fatal(err)
			}

			ephemeralWebKey, err := crypto.AsWebKey(ephemeralKey, "ecdh")

			if err != nil {
				services.Log.Fatal(err)
			}

			queueKey, err := crypto.GenerateKey()

			if err != nil {
				services.Log.Fatal(err)
			}

			queueWebKey, err := crypto.AsWebKey(queueKey, "ecdh")

			if err != nil {
				services.Log.Fatal(err)
			}

			sharedKey := crypto.DeriveKey(queueEncryptionPublicKey, ephemeralKey)

			jsonKey, err := json.Marshal(queueWebKey.PrivateKey)

			if err != nil {
				services.Log.Fatal(err)
			}

			encryptedData, err := crypto.Encrypt(jsonKey, sharedKey)

			if err != nil {
				services.Log.Fatal(err)
			}

			id, err := crypto.RandomBytes(32)

			if err != nil {
				services.Log.Fatal(err)
			}

			decodedEphKey, err := base64.StdEncoding.DecodeString(ephemeralWebKey.PublicKey)

			if err != nil {
				services.Log.Fatal(err)
			}

			decodedQueueKey, err := base64.StdEncoding.DecodeString(queueWebKey.PublicKey)

			if err != nil {
				services.Log.Fatal(err)
			}

			queueData := &services.Queue{
				EncryptedPrivateKey: &services.ECDHEncryptedData{
					IV:        encryptedData.IV,
					Data:      encryptedData.Data,
					PublicKey: decodedEphKey,
				},
				PublicKey: decodedQueueKey,
				Name:      area,
				Type:      "zipArea",
				ID:        id,
				Data: map[string]interface{}{
					"zipArea": area,
				},
			}

			queues = append(queues, queueData)

		}

		jsonData, err := json.MarshalIndent(map[string]interface{}{"queues": queues}, "", "  ")

		if err != nil {
			services.Log.Fatal(err)
		}

		fmt.Println(string(jsonData))

		return nil

	}
}

func setupKeys(settings *services.Settings) func(c *cli.Context) error {
	return func(c *cli.Context) error {

		adminKeys := []*crypto.Key{}
		apptKeys := []*crypto.Key{}

		keys := map[string]string{
			"root":     "ecdsa",
			"token":    "ecdsa",
			"provider": "ecdh",
			"queue":    "ecdh",
		}

		for name, keyType := range keys {
			queueDataKey, err := crypto.GenerateKey()

			if err != nil {
				services.Log.Fatal(err)
			}

			settingsKey, err := crypto.AsSettingsKey(queueDataKey, name, keyType)

			if err != nil {
				services.Log.Fatal(err)
			}
			adminKeys = append(adminKeys, settingsKey)

			keyCopy := *settingsKey

			if name != "token" {
				// we remove all private keys except for the 'token' key, which the backend needs
				// to sign tokens...
				keyCopy.PrivateKey = nil
			}

			apptKeys = append(apptKeys, &keyCopy)

		}

		adminSettings := &services.Settings{
			Admin: &services.AdminSettings{
				Signing: &services.SigningSettings{
					Keys: adminKeys,
				},
			},
		}

		secret, err := crypto.RandomBytes(32)

		if err != nil {
			services.Log.Fatal(err)
		}

		apptSettings := &services.Settings{
			Appointments: &services.AppointmentsSettings{
				Keys:   apptKeys,
				Secret: secret,
			},
		}

		apptJson, err := json.MarshalIndent(apptSettings, "", "  ")

		if err != nil {
			services.Log.Fatal(err)
		}

		adminJson, err := json.MarshalIndent(adminSettings, "", "  ")

		if err != nil {
			services.Log.Fatal(err)
		}

		settingsPaths := helpers.SettingsPaths()

		if len(settingsPaths) == 0 {
			services.Log.Fatal("no settings paths defined!")
		}

		if err := ioutil.WriteFile(fmt.Sprintf("%s/002_admin.json", settingsPaths[0]), adminJson, 0644); err != nil {
			services.Log.Fatal(err)
		}

		if err := ioutil.WriteFile(fmt.Sprintf("%s/003_appt.json", settingsPaths[0]), apptJson, 0644); err != nil {
			services.Log.Fatal(err)
		}

		return nil
	}
}

func uploadDistances(settings *services.Settings) func(c *cli.Context) error {
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

		distances := &UploadDistances{}
		var rawDistances map[string]interface{}

		if err := json.Unmarshal(jsonBytes, &rawDistances); err != nil {
			services.Log.Fatal(err)
		}

		if params, err := UploadDistancesForm.Validate(rawDistances); err != nil {
			services.Log.Fatal(err)
		} else if UploadDistancesForm.Coerce(distances, params); err != nil {
			services.Log.Fatal(err)
		}

		client := jsonrpc.MakeClient(settings.Admin.Client.AppointmentsEndpoint)

		signingKey := settings.Admin.Signing.Key("root")

		if signingKey == nil {
			services.Log.Fatal("can't find signing key")
		}

		i := 0
		allDistances := distances.Distances

		N := 10000

		// we chunk the distances up
		for i < len(allDistances) {

			j := i + N
			if j >= len(allDistances) {
				j = len(allDistances)
			}

			services.Log.Infof("Submitting distances [%d, %d] from %d in total...", i, j, len(allDistances))

			t := time.Now()
			distances.Timestamp = &t
			distances.Distances = allDistances[i:j]

			i += N

			bytes, err := json.Marshal(distances)

			if err != nil {
				services.Log.Fatal(err)
			}

			signedData, err := signingKey.SignString(string(bytes))

			if err != nil {
				services.Log.Fatal(err)
			}

			request := jsonrpc.MakeRequest("uploadDistances", "", signedData.AsMap())

			if response, err := client.Call(request); err != nil {
				services.Log.Fatal(err)
			} else {
				services.Log.Info(response.AsJSON())
			}

		}

		return nil
	}
}

func generateCodes(settings *services.Settings) func(c *cli.Context) error {
	return func(c *cli.Context) error {

		if settings.Admin == nil {
			services.Log.Fatal("admin settings missing")
		}

		n := c.Int("n")

		if n < 0 || n > 1000000 {
			services.Log.Fatal("n should be between 0 and 1.000.000")
		}

		actor := c.String("actor")

		if actor != "user" && actor != "provider" {
			services.Log.Fatal("actor should be 'user' or 'provider'")
		}

		codes := []string{}

		for i := 0; i < n; i++ {
			code, err := crypto.RandomBytes(16)
			if err != nil {
				services.Log.Fatal(err)
			}
			codes = append(codes, hex.EncodeToString(code))
		}

		jsonData, err := json.MarshalIndent(map[string]interface{}{
			"actor": actor,
			"codes": codes,
		}, "", "  ")

		if err != nil {
			services.Log.Fatal(err)
		}

		fmt.Println(string(jsonData))

		return nil
	}
}

var CodesForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "actor",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"provider", "user"}},
			},
		},
		{
			Name: "codes",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsHex{
							ConvertToBinary: false,
							Strict:          true,
							MinLength:       16,
							MaxLength:       32,
						},
					},
				},
			},
		},
	},
}

type Codes struct {
	Actor     string     `json:"actor"`
	Codes     []string   `json:"codes"`
	Timestamp *time.Time `json:"timestamp"`
}

func uploadCodes(settings *services.Settings) func(c *cli.Context) error {
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

		codes := &Codes{}
		var rawCodes map[string]interface{}

		if err := json.Unmarshal(jsonBytes, &rawCodes); err != nil {
			services.Log.Fatal(err)
		}

		if params, err := CodesForm.Validate(rawCodes); err != nil {
			services.Log.Fatal(err)
		} else if CodesForm.Coerce(codes, params); err != nil {
			services.Log.Fatal(err)
		}

		client := jsonrpc.MakeClient(settings.Admin.Client.AppointmentsEndpoint)

		signingKey := settings.Admin.Signing.Key("root")

		if signingKey == nil {
			services.Log.Fatal("can't find signing key")
		}

		i := 0
		allCodes := codes.Codes

		N := 100

		// we chunk the distances up
		for i < len(allCodes) {

			j := i + N
			if j >= len(allCodes) {
				j = len(allCodes)
			}

			services.Log.Infof("Submitting codes [%d, %d] from %d in total...", i, j, len(allCodes))

			t := time.Now()
			codes.Timestamp = &t
			codes.Codes = allCodes[i:j]

			i += N

			bytes, err := json.Marshal(codes)

			if err != nil {
				services.Log.Fatal(err)
			}

			signedData, err := signingKey.SignString(string(bytes))

			if err != nil {
				services.Log.Fatal(err)
			}

			request := jsonrpc.MakeRequest("addCodes", "", signedData.AsMap())

			if response, err := client.Call(request); err != nil {
				services.Log.Fatal(err)
			} else {
				services.Log.Info(response.AsJSON())
			}
		}

		return nil
	}
}

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
					Name:  "codes",
					Flags: []cli.Flag{},
					Usage: "Codes-related command.",
					Subcommands: []cli.Command{
						{
							Name: "generate",
							Flags: []cli.Flag{
								&cli.IntFlag{
									Name:  "n",
									Value: 10000,
									Usage: "number of codes to generate",
								},
								&cli.StringFlag{
									Name:  "actor",
									Value: "user",
									Usage: "actor for which to generate codes (user or provider)",
								},
							},
							Usage:  "generate codes for users or providers",
							Action: generateCodes(settings),
						},
						{
							Name:   "upload",
							Flags:  []cli.Flag{},
							Usage:  "upload codes from a file to the backend",
							Action: uploadCodes(settings),
						},
					},
				},
				{
					Name:  "keys",
					Flags: []cli.Flag{},
					Usage: "Keys-related command.",
					Subcommands: []cli.Command{
						{
							Name:   "setup",
							Flags:  []cli.Flag{},
							Usage:  "set up keys for the given environment",
							Action: setupKeys(settings),
						},
						{
							Name:   "mediator",
							Flags:  []cli.Flag{},
							Usage:  "generate a new set of mediator keys",
							Action: generateMediatorKeys(settings),
						},
					},
				},
				{
					Name:  "distances",
					Flags: []cli.Flag{},
					Usage: "Distances-related command.",
					Subcommands: []cli.Command{
						{
							Name:   "upload",
							Flags:  []cli.Flag{},
							Usage:  "upload distances from a file to the backend",
							Action: uploadDistances(settings),
						},
					},
				},
				{
					Name:  "queues",
					Flags: []cli.Flag{},
					Usage: "Queues-related command.",
					Subcommands: []cli.Command{
						{
							Name:   "generate",
							Flags:  []cli.Flag{},
							Usage:  "generate queues for all relevant zip codes",
							Action: generateQueues(settings),
						},
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
							Name:   "upload",
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
