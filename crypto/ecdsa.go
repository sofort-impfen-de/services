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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
)

// https://thanethomson.com/2018/11/30/validating-ecdsa-signatures-golang/

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

type JWKPrivateKey struct {
	Curve       string   `json:"crv"`
	D           string   `json:"d"`
	Extractable bool     `json:"ext"`
	KeyOps      []string `json:"key_ops"`
	KeyType     string   `json:"kty"`
	X           string   `json:"x"`
	Y           string   `json:"y"`
}

type WebKey struct {
	// PKIX ASN.1 DER format
	PublicKey string `json:"publicKey"`
	// JWK format (as Firefox can't parse PKCS8...)
	PrivateKey *JWKPrivateKey `json:"privateKey"`
}

func AsSettingsKey(key *ecdsa.PrivateKey, name, keyType string) (*Key, error) {
	marshalledPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	marshalledPrivateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	var purposes []string

	switch keyType {
	case "ecdh":
		purposes = []string{"deriveKey"}
	case "ecdsa":
		purposes = []string{"sign", "verify"}
	}

	return &Key{
		Type:       keyType,
		PublicKey:  marshalledPublicKey,
		PrivateKey: marshalledPrivateKey,
		Purposes:   purposes,
		Params: map[string]interface{}{
			"curve": "p-256",
		},
		Name:   name,
		Format: "spki-pkcs8",
	}, nil

}

func AsWebKey(key *ecdsa.PrivateKey, keyType string) (*WebKey, error) {
	marshalledPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	var ops []string

	switch keyType {
	case "ecdh":
		ops = []string{"deriveKey"}
	case "ecdsa":
		ops = []string{"sign", "verify"}
	}

	return &WebKey{
		PublicKey: base64.StdEncoding.EncodeToString(marshalledPublicKey),
		PrivateKey: &JWKPrivateKey{
			Curve:       key.Params().Name,
			D:           base64.RawURLEncoding.EncodeToString(key.D.Bytes()),
			Extractable: true,
			KeyOps:      ops,
			KeyType:     "EC",
			X:           base64.RawURLEncoding.EncodeToString(key.X.Bytes()),
			Y:           base64.RawURLEncoding.EncodeToString(key.Y.Bytes()),
		},
	}, nil
}

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

func VerifyWithBytes(message, signature, publicKeyData []byte) (bool, error) {
	if publicKey, err := LoadPublicKey(publicKeyData); err != nil {
		return false, err
	} else {
		return Verify(message, signature, publicKey)
	}
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
