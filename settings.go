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
	RPC             *JSONRPCServerSettings `json:"rpc"`
}

type AppointmentsSettings struct {
	RPC  *JSONRPCServerSettings `json:"rpc"`
	Keys []*Key                 `json:"keys"`
}

func (a *AppointmentsSettings) Key(name string) *Key {
	return key(a.Keys, name)
}

func key(keys []*Key, name string) *Key {
	for _, key := range keys {
		if key.Name == name {
			return key
		}
	}
	return nil
}

type Key struct {
	Name      string                 `json:"name"`
	Type      string                 `json:"type"`
	Format    string                 `json:"format"`
	Params    map[string]interface{} `json:"params"`
	PublicKey []byte                 `json:"public_key"`
	Purposes  []string               `json:"purposes"`
	// only defined for local signing operations
	PrivateKey []byte `json:"private_key"`
}

type SignedStringData struct {
	Data      string `json:"data"`
	Signature []byte `json:"signature"`
	PublicKey []byte `json:"publicKey"`
}

func (s *SignedStringData) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"data":      s.Data,
		"signature": s.Signature,
		"publicKey": s.PublicKey,
	}
}

type SignedData struct {
	Data      []byte `json:"data"`
	Signature []byte `json:"signature"`
	PublicKey []byte `json:"publicKey"`
}

func (s *SignedData) AsMap() map[string]interface{} {
	return map[string]interface{}{
		"data":      s.Data,
		"signature": s.Signature,
		"publicKey": s.PublicKey,
	}
}

func (k *Key) SignString(data string) (*SignedStringData, error) {
	if signature, err := k.Sign([]byte(data)); err != nil {
		return nil, err
	} else {
		return &SignedStringData{
			Data:      string(signature.Data),
			Signature: signature.Signature,
			PublicKey: signature.PublicKey,
		}, nil
	}
}

func (k *Key) Sign(data []byte) (*SignedData, error) {
	if privateKey, err := crypto.LoadPrivateKey(k.PrivateKey); err != nil {
		return nil, err
	} else if signature, err := crypto.Sign(data, privateKey); err != nil {
		return nil, err
	} else {
		return &SignedData{
			Data:      data,
			Signature: signature.Serialize(),
			PublicKey: k.PublicKey,
		}, nil
	}
}

func (k *Key) Verify(data *SignedData) (bool, error) {
	if publicKey, err := crypto.LoadPublicKey(k.PublicKey); err != nil {
		return false, err
	} else {
		return crypto.Verify(data.Data, data.Signature, publicKey)
	}
}

func (s *SigningSettings) Key(name string) *Key {
	return key(s.Keys, name)
}

type SigningSettings struct {
	Keys []*Key `json:"keys"`
}

type DatabaseSettings struct {
	Type     string `json:"type"`
	Settings interface{}
}

type Settings struct {
	Admin        *AdminSettings        `json:"admin"`
	Definitions  *Definitions          `json:"definitions"`
	Storage      *StorageSettings      `json:"storage"`
	Appointments *AppointmentsSettings `json:"appointments"`
	Database     *DatabaseSettings     `json:"database"`
}

type AdminSettings struct {
	Signing *SigningSettings `json:"signing"`
	Client  *ClientSettings  `json:"client"`
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
	Cors        *CorsSettings `json:"cors"`
	TLS         *TLSSettings  `json:"tls"`
	BindAddress string        `json:"bind_address"`
}

// Settings for the JSON-RPC server
type HTTPServerSettings struct {
	TLS         *TLSSettings `json:"tls"`
	BindAddress string       `json:"bind_address"`
}
