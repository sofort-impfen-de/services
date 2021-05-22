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

package forms

import (
	"github.com/kiprotect/go-helpers/forms"
)

var SigningForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "key_file",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
	},
}

var DatabaseForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "name",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "type",
			Validators: []forms.Validator{
				forms.IsString{},
				IsValidDatabaseType{},
			},
		},
		{
			Name: "settings",
			Validators: []forms.Validator{
				forms.IsStringMap{},
				AreValidDatabaseSettings{},
			},
		},
	},
}

var StorageForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "rpc",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &JSONRPCServerSettingsForm,
				},
			},
		},
		// how long we want to store settings
		{
			Name: "settings_ttl_days",
			Validators: []forms.Validator{
				forms.IsInteger{
					HasMin: true,
					Min:    1,
					HasMax: true,
					Max:    60,
				},
			},
		},
	},
}

var ECDSAParamsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "curve",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"p-256"}}, // we only support P-256
			},
		},
	},
}

var RootKeyForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "type",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"ecdsa"}}, // we only support ECDSA for now
			},
		},
		{
			Name: "format",
			Validators: []forms.Validator{
				forms.IsIn{Choices: []interface{}{"spki"}}, // we only support SPKI for now
			},
		},
		{
			Name: "params",
			Validators: []forms.Validator{
				forms.Switch{
					Key: "type",
					Cases: map[string][]forms.Validator{
						"ecdsa": []forms.Validator{
							forms.IsStringMap{
								Form: &ECDSAParamsForm,
							},
						},
					},
				},
			},
		},
	},
}

var AppointmentsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "root_keys",
			Validators: []forms.Validator{
				forms.IsList{
					Validators: []forms.Validator{
						forms.IsStringMap{
							Form: &RootKeyForm,
						},
					},
				},
			},
		},
		{
			Name: "rpc",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &JSONRPCServerSettingsForm,
				},
			},
		},
	},
}

var SettingsForm = forms.Form{
	Fields: []forms.Field{
		{
			Name: "name",
			Validators: []forms.Validator{
				forms.IsString{},
			},
		},
		{
			Name: "database",
			Validators: []forms.Validator{
				forms.IsStringMap{
					Form: &DatabaseForm,
				},
			},
		},
		{
			Name: "storage",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{
					Form: &StorageForm,
				},
			},
		},
		{
			Name: "appointments",
			Validators: []forms.Validator{
				forms.IsOptional{},
				forms.IsStringMap{
					Form: &AppointmentsForm,
				},
			},
		},
	},
}
