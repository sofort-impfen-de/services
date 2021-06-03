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

package main

import (
	"github.com/kiebitz-oss/services"
	cmdHelpers "github.com/kiebitz-oss/services/cmd/helpers"
	"github.com/kiebitz-oss/services/definitions"
	"github.com/kiebitz-oss/services/helpers"
)

func Settings(definitions *services.Definitions) (*services.Settings, error) {
	settingsPaths := helpers.SettingsPaths()
	return helpers.Settings(settingsPaths, definitions)
}

func main() {
	if settings, err := Settings(&definitions.Default); err != nil {
		services.Log.Fatal(err)
	} else if db, err := helpers.InitializeDatabase(settings); err != nil {
		services.Log.Fatal(err)
	} else if meter, err := helpers.InitializeMeter(settings); err != nil {
		services.Log.Fatal(err)
	} else {
		settings.DatabaseObj = db
		settings.MeterObj = meter
		cmdHelpers.CLI(settings)
	}
}
