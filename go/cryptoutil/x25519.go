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

func (a *X25519Algorithm) GetKeyFormat() payloadpb.KeyFormat {
	return payloadpb.KeyFormat_KeyFormatX25519
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
			Key: privateKey,
		},
		Public: &X25519PublicKey{
			Key: privateKey.PublicKey(),
		},
	}
	return keyPair, nil
}

func (a *X25519Algorithm) UnmarshalPublicKey(input []byte) (PublicKey, error) {
	return a.UnmarshalDHPublicKey(input)
}

func (a *X25519Algorithm) UnmarshalDHPublicKey(input []byte) (DHPublicKey, error) {
	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(input)
	if err != nil {
		return nil, err
	}
	return &X25519PublicKey{
		Key: publicKey,
	}, nil
}

type X25519PrivateKey struct {
	Key *ecdh.PrivateKey
}

func (k *X25519PrivateKey) IsDHKey() bool {
	return true
}

func (k *X25519PrivateKey) IsSignatureKey() bool {
	return false
}

func (k *X25519PrivateKey) GetDHPublic() DHPublicKey {
	return &X25519PublicKey{
		Key: k.Key.PublicKey(),
	}
}

func (k *X25519PrivateKey) GetPublic() PublicKey {
	return k.GetDHPublic()
}

func (k *X25519PrivateKey) Algorithm() PublicAlgorithm {
	return &x25519Algorithm
}

func (k *X25519PrivateKey) GetDHAlgorithm() DHAlgorithm {
	return &x25519Algorithm
}

func (k *X25519PrivateKey) GetDHAlgorithmProto() payloadpb.DHAlgorithm {
	return payloadpb.DHAlgorithm_DHX25519
}

func (k *X25519PrivateKey) DH(peerKey DHPublicKey) ([]byte, error) {
	publicKey, ok := peerKey.(*X25519PublicKey)
	if !ok {
		return nil, errors.New("peerKey is not x25519")
	}
	return k.Key.ECDH(publicKey.Key)
}

type X25519PublicKey struct {
	Key *ecdh.PublicKey
}

func (k *X25519PublicKey) IsDHKey() bool {
	return true
}

func (k *X25519PublicKey) IsSignatureKey() bool {
	return false
}

func (k *X25519PublicKey) Algorithm() PublicAlgorithm {
	return &x25519Algorithm
}

func (k *X25519PublicKey) GetDHAlgorithm() DHAlgorithm {
	return &x25519Algorithm
}

func (k *X25519PublicKey) GetDHAlgorithmProto() payloadpb.DHAlgorithm {
	return payloadpb.DHAlgorithm_DHX25519
}

func (k *X25519PublicKey) Marshal() []byte {
	return k.Key.Bytes()
}

func (k *X25519PublicKey) MarshalToProto() (*payloadpb.PublicKey, error) {
	return &payloadpb.PublicKey{
		Format: payloadpb.KeyFormat_KeyFormatX25519,
		Data:   k.Marshal(),
	}, nil
}
