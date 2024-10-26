package cryptoutil

import (
	"crypto/ecdh"
	"crypto/rand"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/pkg/errors"
)

var x25519Algorithm X25519Algorithm

type X25519Algorithm struct {
}

func (a *X25519Algorithm) GetType() payloadpb.DHAlgorithm {
	return payloadpb.DHAlgorithm_DHX25519
}

func (a *X25519Algorithm) Generate() (*DHKeyPair, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyPair := &DHKeyPair{
		Private: &X25519PrivateKey{
			key: privateKey,
		},
		Public: &X25519PublicKey{
			key: privateKey.PublicKey(),
		},
	}
	return keyPair, nil
}

func (a *X25519Algorithm) UnmarshalPublicKey(input []byte) (DHPublicKey, error) {
	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(input)
	if err != nil {
		return nil, err
	}
	return &X25519PublicKey{
		key: publicKey,
	}, nil
}

type X25519PrivateKey struct {
	key *ecdh.PrivateKey
}

func (k *X25519PrivateKey) Algorithm() DHAlgorithm {
	return &x25519Algorithm
}

func (k *X25519PrivateKey) DH(peerKey DHPublicKey) ([]byte, error) {
	publicKey, ok := peerKey.(*X25519PublicKey)
	if !ok {
		return nil, errors.New("peerKey is not x25519")
	}
	return k.key.ECDH(publicKey.key)
}

type X25519PublicKey struct {
	key *ecdh.PublicKey
}

func (k *X25519PublicKey) Algorithm() DHAlgorithm {
	return &x25519Algorithm
}

func (k *X25519PublicKey) Marshal() []byte {
	return k.key.Bytes()
}
