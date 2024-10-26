package sessionstate

import (
	"crypto/sha256"
	"fmt"
	"github.com/jc-lab/jscp/go/cryptoutil"
)

// SymmetricState represents the symmetric state during the Noise Protocol handshake
type SymmetricState struct {
	ck []byte
	h  []byte
	cs *CipherState
}

// NewSymmetricState creates a new SymmetricState instance
func NewSymmetricState() *SymmetricState {
	return &SymmetricState{
		ck: nil,
		h:  nil,
		cs: nil,
	}
}

// MixHash mixes the given data into the hash state
func (s *SymmetricState) MixHash(data []byte) {
	h := sha256.Sum256(append(s.h, data...))
	s.h = h[:]
}

// MixKey mixes a new key into the state using HKDF
func (s *SymmetricState) MixKey(cipher cryptoutil.CipherAlgorithm, key []byte) {
	ck, temp := cryptoutil.Hkdf(key, s.ck)
	s.ck = ck
	s.cs = NewCipherState(cipher, temp)
}

// EncryptAndMixHash encrypts the plaintext and mixes the ciphertext into the state
func (s *SymmetricState) EncryptAndMixHash(plaintext []byte, mustSecret bool) ([]byte, error) {
	var ciphertext []byte

	if s.cs != nil {
		var err error
		nonce := s.cs.Nonce.GetBytes()
		ciphertext, err = s.cs.Cipher.Seal(s.cs.Key, nonce, plaintext, s.h)
		if err != nil {
			return nil, err
		}
		s.cs.Nonce.Increment()
	} else {
		if mustSecret {
			return nil, fmt.Errorf("must secret")
		}
		ciphertext = plaintext
	}

	s.MixHash(ciphertext)
	return ciphertext, nil
}

// MixHashAndDecrypt decrypts the ciphertext and mixes it into the state
func (s *SymmetricState) MixHashAndDecrypt(ciphertext []byte) ([]byte, error) {
	if s.cs != nil {
		nonce := s.cs.Nonce.GetBytes()
		plaintext, err := s.cs.Cipher.Open(s.cs.Key, nonce, ciphertext, s.h)
		if err != nil {
			return nil, err
		}
		s.MixHash(ciphertext)
		s.cs.Nonce.Increment()
		return plaintext, nil
	}

	s.MixHash(ciphertext)
	return ciphertext, nil
}