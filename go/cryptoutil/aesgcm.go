package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/jc-lab/jscp/go/payloadpb"
)

type AesGcmCipher struct {
}

func (c *AesGcmCipher) GetType() payloadpb.CipherAlgorithm {
	return payloadpb.CipherAlgorithm_CipherAesGcm
}

func (c *AesGcmCipher) Seal(key []byte, nonce []byte, plaintext []byte, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Seal(nil, nonce, plaintext, ad), nil
}

func (c *AesGcmCipher) Open(key []byte, nonce []byte, ciphertext []byte, ad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, ad)
}
