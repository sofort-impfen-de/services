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
	"github.com/kiebitz-oss/services/helpers"
	"github.com/urfave/cli"
	"os"
)

type decorator func(f func(c *cli.Context) error) func(c *cli.Context) error

func decorate(commands []cli.Command, decorator decorator) []cli.Command {
	newCommands := make([]cli.Command, len(commands))
	for i, command := range commands {
		if command.Action != nil {
			command.Action = decorator(command.Action.(func(c *cli.Context) error))
		}
		if command.Subcommands != nil {
			command.Subcommands = decorate(command.Subcommands, decorator)
		}
		newCommands[i] = command
	}
	return newCommands
}

func Settings(definitions *services.Definitions) (*services.Settings, error) {
	settingsPaths := helpers.SettingsPaths()
	return helpers.Settings(settingsPaths, definitions)
}

func CLI(settings *services.Settings) {

	var err error

	init := func(f func(c *cli.Context) error) func(c *cli.Context) error {
		return func(c *cli.Context) error {

			level := c.GlobalString("level")
			logLevel, err := services.ParseLevel(level)
			if err != nil {
				return err
			}
			services.Log.SetLevel(logLevel)

			runner := func() error { return f(c) }
			profiler := c.GlobalString("profile")
			if profiler != "" {
				return runWithProfiler(profiler, runner)
			}

			return f(c)
		}
	}

	app := cli.NewApp()
	app.Name = "Kiebitz"
	app.Usage = "Run all Kiebitz commands"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "level",
			Value: "info",
			Usage: "The desired log level",
		},
		cli.StringFlag{
			Name:  "profile",
			Value: "",
			Usage: "enable profiler and store results to given filename",
		},
	}

	bareCommands := []cli.Command{}

	// we add commands from the definitions
	for _, commandsDefinition := range settings.Definitions.CommandsDefinitions {
		if commands, err := commandsDefinition.Maker(settings); err != nil {
			services.Log.Fatal(err)
		} else {
			bareCommands = append(bareCommands, commands...)
		}
	}

	app.Commands = decorate(bareCommands, init)

	err = app.Run(os.Args)

	if err != nil {
		services.Log.Error(err)
	}

}
