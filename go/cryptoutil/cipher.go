package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"github.com/jc-lab/jscp/go/payloadpb"
)

// Encrypt encrypts the plaintext using AES-GCM
func Encrypt(algorithm payloadpb.CryptoAlgorithm, dest *payloadpb.EncryptedMessage, key, authData, plaintext []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	nonce := dest.Nonce
	if len(nonce) <= 0 {
		nonce = make([]byte, 12)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		dest.Nonce = nonce
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, authData)
	dest.Ciphertext = ciphertext
	return nil
}

// Decrypt decrypts the ciphertext using AES-GCM
func Decrypt(algorithm payloadpb.CryptoAlgorithm, key []byte, authData []byte, input *payloadpb.EncryptedMessage) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, input.Nonce, input.Ciphertext, authData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
