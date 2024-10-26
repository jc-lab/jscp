package sessionstate

import "github.com/jc-lab/jscp/go/cryptoutil"

type CipherState struct {
	Cipher cryptoutil.CipherAlgorithm
	Nonce  *Nonce
	Key    []byte
}

func NewCipherState(cipher cryptoutil.CipherAlgorithm, key []byte) *CipherState {
	return &CipherState{
		Cipher: cipher,
		Nonce:  NewNonce(12),
		Key:    key,
	}
}
