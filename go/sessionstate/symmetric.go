package sessionstate

import (
	"crypto/sha256"
	"fmt"
	"github.com/jc-lab/jscp/go/cryptoutil"
)

type SymmetricState interface {
	HasKey() bool
	MixHash(data []byte)
	MixKey(cipher cryptoutil.CipherAlgorithm, key []byte)
	EncryptWithAd(plaintext []byte, ad []byte) ([]byte, error)
	DecryptWithAd(ciphertext []byte, ad []byte) ([]byte, error)
	EncryptAndMixHash(plaintext []byte, mustSecret bool) ([]byte, error)
	MixHashAndDecrypt(ciphertext []byte) ([]byte, error)
}

// SymmetricStateImpl represents the symmetric state during the Noise Protocol handshake
type SymmetricStateImpl struct {
	ck []byte
	h  []byte
	cs *CipherState
}

// NewSymmetricState creates a new SymmetricState instance
func NewSymmetricState() SymmetricState {
	return &SymmetricStateImpl{
		ck: nil,
		h:  nil,
		cs: nil,
	}
}

func (s *SymmetricStateImpl) HasKey() bool {
	return s.cs != nil
}

// MixHash mixes the given data into the hash state
func (s *SymmetricStateImpl) MixHash(data []byte) {
	h := sha256.Sum256(append(s.h, data...))
	s.h = h[:]
}

// MixKey mixes a new key into the state using HKDF
func (s *SymmetricStateImpl) MixKey(cipher cryptoutil.CipherAlgorithm, key []byte) {
	ck, temp := cryptoutil.Hkdf(key, s.ck)
	s.ck = ck
	s.cs = NewCipherState(cipher, temp)
}

func (s *SymmetricStateImpl) EncryptWithAd(plaintext []byte, ad []byte) ([]byte, error) {
	nonce := s.cs.Nonce.GetBytes()
	ciphertext, err := s.cs.Cipher.Seal(s.cs.Key, nonce, plaintext, ad)
	if err != nil {
		return nil, err
	}
	s.cs.Nonce.Increment()
	return ciphertext, err
}

func (s *SymmetricStateImpl) DecryptWithAd(ciphertext []byte, ad []byte) ([]byte, error) {
	nonce := s.cs.Nonce.GetBytes()
	plaintext, err := s.cs.Cipher.Open(s.cs.Key, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	s.cs.Nonce.Increment()
	return plaintext, nil
}

// EncryptAndMixHash encrypts the plaintext and mixes the ciphertext into the state
func (s *SymmetricStateImpl) EncryptAndMixHash(plaintext []byte, mustSecret bool) ([]byte, error) {
	var ciphertext []byte

	if s.cs != nil {
		var err error
		ciphertext, err = s.EncryptWithAd(plaintext, s.h)
		if err != nil {
			return nil, err
		}
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
func (s *SymmetricStateImpl) MixHashAndDecrypt(ciphertext []byte) ([]byte, error) {
	var plaintext []byte

	if s.cs != nil {
		var err error
		plaintext, err = s.DecryptWithAd(ciphertext, s.h)
		if err != nil {
			return nil, err
		}
	} else {
		plaintext = ciphertext
	}

	s.MixHash(ciphertext)

	return plaintext, nil
}
