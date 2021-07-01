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
)

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

func (s *SignedData) Verify(publicKey *ecdsa.PublicKey) (bool, error) {
	return Verify([]byte(s.Data), s.Signature, publicKey)
}
