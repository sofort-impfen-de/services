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
