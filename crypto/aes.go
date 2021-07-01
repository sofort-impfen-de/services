package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type EncryptedData struct {
	IV   []byte `json:"iv"`
	Data []byte `json:"data"`
}

func Encrypt(data, key []byte) (*EncryptedData, error) {
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		return nil, err
	}

	return &EncryptedData{Data: gcm.Seal(nil, iv, data, nil), IV: iv}, nil
}

func Decrypt(data *EncryptedData, key []byte) ([]byte, error) {
	return nil, nil
}
