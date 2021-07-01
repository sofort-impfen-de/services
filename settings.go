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

package services

import (
	"github.com/kiebitz-oss/services/crypto"
)

type RPCSettings struct {
	BindAddress string `json:"bind_address"`
}

type StorageSettings struct {
	SettingsTTLDays int64                  `json:"settings_ttl_days"`
	RPC             *JSONRPCServerSettings `json:"rpc,omitempty"`
}

type AppointmentsSettings struct {
	DataTTLDays          int64                  `json:"data_ttl_days,omitempty"`
	RPC                  *JSONRPCServerSettings `json:"rpc,omitempty"`
	Keys                 []*crypto.Key          `json:"keys,omitempty"`
	Secret               []byte                 `json:"secret,omitempty"`
	ProviderCodesEnabled bool                   `json:"provider_codes_enabled,omitempty"`
	UserCodesEnabled     bool                   `json:"user_codes_enabled,omitempty"`
}

func (a *AppointmentsSettings) Key(name string) *crypto.Key {
	return key(a.Keys, name)
}

func key(keys []*crypto.Key, name string) *crypto.Key {
	for _, key := range keys {
		if key.Name == name {
			return key
		}
	}
	return nil
}

func (s *SigningSettings) Key(name string) *crypto.Key {
	return key(s.Keys, name)
}

type SigningSettings struct {
	Keys []*crypto.Key `json:"keys"`
}

type DatabaseSettings struct {
	Type     string `json:"type"`
	Settings interface{}
}

type MeterSettings struct {
	Type     string `json:"type"`
	Settings interface{}
}

type Settings struct {
	Admin        *AdminSettings        `json:"admin,omitempty"`
	Definitions  *Definitions          `json:"definitions,omitempty"`
	Storage      *StorageSettings      `json:"storage,omitempty"`
	Appointments *AppointmentsSettings `json:"appointments,omitempty"`
	Database     *DatabaseSettings     `json:"database,omitempty"`
	Meter        *MeterSettings        `json:"meter,omitempty"`
	DatabaseObj  Database              `json:"-"`
	MeterObj     Meter                 `json:"-"`
}

type AdminSettings struct {
	Signing *SigningSettings `json:"signing,omitempty"`
	Client  *ClientSettings  `json:"client,omitempty"`
}

type ClientSettings struct {
	StorageEndpoint      string `json:"storage_endpoint"`
	AppointmentsEndpoint string `json:"appointments_endpoint"`
}

type TLSSettings struct {
	CACertificateFile string `json:"ca_certificate_file"`
	CertificateFile   string `json:"certificate_file"`
	KeyFile           string `json:"key_file"`
}

type CorsSettings struct {
	AllowedHeaders []string `json:"allowed_headers"`
	AllowedHosts   []string `json:"allowed_hosts"`
	AllowedMethods []string `json:"allowed_methods"`
}

// Settings for the JSON-RPC server
type JSONRPCServerSettings struct {
	Cors        *CorsSettings `json:"cors,omitempty"`
	TLS         *TLSSettings  `json:"tls,omitempty"`
	BindAddress string        `json:"bind_address"`
}

// Settings for the JSON-RPC server
type HTTPServerSettings struct {
	TLS         *TLSSettings `json:"tls,omitempty"`
	BindAddress string       `json:"bind_address"`
}
