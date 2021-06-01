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
	"github.com/kiebitz-oss/services"
	"github.com/urfave/cli"
)

func Crypto(settings *services.Settings, db services.Database) ([]cli.Command, error) {

	return []cli.Command{
		{
			Name:    "crypto",
			Aliases: []string{"s"},
			Flags:   []cli.Flag{},
			Usage:   "Cryptographic functions.",
			Subcommands: []cli.Command{
				{
					Name:   "sign",
					Flags:  []cli.Flag{},
					Usage:  "Sign a payload.",
					Action: func(c *cli.Context) error { return nil },
				},
			},
		},
	}, nil
}
