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

package crypto

import (
	"crypto/ecdsa"
	"encoding/base64"
)

type StringKeyPair struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type KeyPair struct {
	PrivateKeyBytes []byte            `json:"privateKeyBytes"`
	PublicKeyBytes  []byte            `json:"publicKeyBytes"`
	PrivateKey      *ecdsa.PrivateKey `json:"-"`
	PublicKey       *ecdsa.PublicKey  `json:"-"`
}

func KeyPairFromStrings(keyPair *StringKeyPair) (*KeyPair, error) {
	publicKeyBytes, err := base64.StdEncoding.DecodeString(keyPair.PublicKey)

	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(keyPair.PrivateKey)

	if err != nil {
		return nil, err
	}

	privateKey, err := LoadPrivateKey(privateKeyBytes)

	if err != nil {
		return nil, err
	}

	publicKey, err := LoadPublicKey(publicKeyBytes)

	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PublicKeyBytes:  publicKeyBytes,
		PrivateKeyBytes: privateKeyBytes,
		PublicKey:       publicKey,
		PrivateKey:      privateKey,
	}, nil
}
