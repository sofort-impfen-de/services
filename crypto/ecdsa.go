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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
)

// https://thanethomson.com/2018/11/30/validating-ecdsa-signatures-golang/

func LoadPublicKey(publicKey []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key")
	}
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return pub, nil
	}
	return nil, fmt.Errorf("invalid public key type")
}

func LoadPrivateKey(privateKey []byte) (*ecdsa.PrivateKey, error) {
	priv, err := x509.ParsePKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key")
	}
	switch priv := priv.(type) {
	case *ecdsa.PrivateKey:
		return priv, nil
	}
	return nil, fmt.Errorf("invalid private key type")
}

type ECDSASignature struct {
	R, S *big.Int
}

func (e *ECDSASignature) Serialize() []byte {
	// we simply concatenate the R & S values
	return append(e.R.Bytes(), e.S.Bytes()...)
}

func Verify(message []byte, signatureBytes []byte, publicKey *ecdsa.PublicKey) (bool, error) {
	sig := &ECDSASignature{
		R: &big.Int{},
		S: &big.Int{},
	}

	bl := publicKey.Curve.Params().BitSize / 8

	if len(signatureBytes) != bl*2 {
		return false, fmt.Errorf("expected %d bytes for signature, but got %d", bl, len(signatureBytes))
	}

	sig.R.SetBytes(signatureBytes[0:32])
	sig.S.SetBytes(signatureBytes[32:])

	hash := sha256.Sum256(message)

	valid := ecdsa.Verify(
		publicKey,
		hash[:],
		sig.R,
		sig.S,
	)
	if !valid {
		return false, nil
	}
	return true, nil
}

func Sign(message []byte, privateKey *ecdsa.PrivateKey) (*ECDSASignature, error) {

	hash := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(
		rand.Reader,
		privateKey,
		hash[:],
	)
	if err != nil {
		return nil, err
	}

	return &ECDSASignature{
		R: r,
		S: s,
	}, nil
}
