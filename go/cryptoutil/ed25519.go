package cryptoutil

import (
	"crypto/rand"
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
	"golang.org/x/crypto/ed25519"
)

var ed25519Algorithm Ed25519Algorithm

type Ed25519Algorithm struct {
}

func (a *Ed25519Algorithm) GetType() payloadpb.SignatureAlgorithm {
	return payloadpb.SignatureAlgorithm_SignatureEd25519
}

func (a *Ed25519Algorithm) UnmarshalPublicKey(input []byte) (SignaturePublicKey, error) {
	publicKey := ed25519.PublicKey(input)
	if len(input) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Key size expected=%d, actual=%d", ed25519.PublicKeySize, len(input))
	}
	instance := &Ed25519PublicKey{
		Key: publicKey,
	}
	return instance, nil
}

func (a *Ed25519Algorithm) Generate() (*Ed25519PrivateKey, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519PrivateKey{
		Key: privateKey,
	}, nil
}

type Ed25519PublicKey struct {
	Key ed25519.PublicKey
}

func (k *Ed25519PublicKey) Algorithm() SignatureAlgorithm {
	return &ed25519Algorithm
}

func (k *Ed25519PublicKey) Verify(data []byte, signature []byte) (bool, error) {
	return ed25519.Verify(k.Key, data, signature), nil
}

func (k *Ed25519PublicKey) MarshalToProto() (*payloadpb.SignaturePublicKey, error) {
	return &payloadpb.SignaturePublicKey{
		Algorithm: k.Algorithm().GetType(),
		Data:      k.Key,
	}, nil
}

type Ed25519PrivateKey struct {
	Key ed25519.PrivateKey
}

func (k *Ed25519PrivateKey) Algorithm() SignatureAlgorithm {
	return &ed25519Algorithm
}

func (k *Ed25519PrivateKey) GetPublic() SignaturePublicKey {
	return &Ed25519PublicKey{
		Key: k.Key.Public().(ed25519.PublicKey),
	}
}

func (k *Ed25519PrivateKey) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(k.Key, data), nil
}
