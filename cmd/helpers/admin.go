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

func uploadQueueData(settings *services.Settings, db services.Database) func(c *cli.Context) error {
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

		services.Log.Info(queues)

		client := jsonrpc.MakeClient(settings.Admin.Client.AppointmentsEndpoint)

		data := map[string]interface{}{
			"queues":    queues.Queues,
			"timestamp": time.Now(),
		}

		services.Log.Info(settings.Admin.Signing.Keys)

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

func Admin(settings *services.Settings, db services.Database) ([]cli.Command, error) {

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
							Action: uploadQueueData(settings, db),
						},
					},
				},
			},
		},
	}, nil
}
