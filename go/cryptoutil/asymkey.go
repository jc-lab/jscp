package cryptoutil

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
)

type OpKeyPair struct {
	PrivateKey OpPrivateKey
	PublicKey  OpPublicKey
}

type OpPublicKey interface {
	ToPublicKeyProto() (*payloadpb.PublicKey, error)
	Verify(data []byte, sig []byte) bool
}

type OpPrivateKey interface {
	ToPublic() (OpPublicKey, error)
	DhAgreement(publicKey OpPublicKey) ([]byte, error)
	Sign(data []byte) ([]byte, error)
}

func GenerateKeyPair(keyType payloadpb.KeyType) (*OpKeyPair, error) {
	switch keyType {
	case payloadpb.KeyType_KeyTypeSignatureEd25519:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &OpKeyPair{
			PrivateKey: &cryptoPrivateKey{
				KeyType:    payloadpb.KeyType_KeyTypeSignatureEd25519,
				PrivateKey: privateKey,
			},
			PublicKey: &cryptoPublicKey{
				KeyType:   payloadpb.KeyType_KeyTypeSignatureEd25519,
				PublicKey: publicKey,
				Bytes:     publicKey,
			},
		}, nil
	case payloadpb.KeyType_KeyTypeDHX25519:
		curve := ecdh.X25519()
		privateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &OpKeyPair{
			PrivateKey: &ecdhPrivateKey{
				KeyType:    keyType,
				PrivateKey: privateKey,
			},
			PublicKey: &ecdhPublicKey{
				KeyType:   keyType,
				PublicKey: privateKey.PublicKey(),
			},
		}, nil
	}
	return nil, fmt.Errorf("invalid key type: %v", keyType)
}

func UnmarshalFromPrivateKeyProto(input *payloadpb.PrivateKey) (*OpKeyPair, error) {
	var privateKey OpPrivateKey
	switch input.KeyType {
	case payloadpb.KeyType_KeyTypeSignatureEd25519:
		if len(input.Data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid size %d expected %d", len(input.Data), ed25519.PublicKeySize)
		}
		rawPrivateKey := ed25519.PrivateKey(input.Data)
		privateKey = &cryptoPrivateKey{
			KeyType:    input.KeyType,
			PrivateKey: rawPrivateKey,
		}
	case payloadpb.KeyType_KeyTypeDHX25519:
		curve := ecdh.X25519()
		rawPrivateKey, err := curve.NewPrivateKey(input.Data)
		if err != nil {
			return nil, err
		}
		privateKey = &ecdhPrivateKey{
			KeyType:    input.KeyType,
			PrivateKey: rawPrivateKey,
		}
	}
	if privateKey == nil {
		return nil, fmt.Errorf("invalid key type: %v", input.KeyType)
	}

	publicKey, err := privateKey.ToPublic()
	if err != nil {
		return nil, err
	}
	return &OpKeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func UnmarshalFromPublicKeyProto(input *payloadpb.PublicKey) (OpPublicKey, error) {
	switch input.KeyType {
	case payloadpb.KeyType_KeyTypeSignatureEd25519:
		if len(input.Data) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid size %d expected %d", len(input.Data), ed25519.PublicKeySize)
		}
		publicKey := ed25519.PublicKey(input.Data)
		return &cryptoPublicKey{
			KeyType:   payloadpb.KeyType_KeyTypeSignatureEd25519,
			PublicKey: publicKey,
			Bytes:     publicKey,
			verify: func(data []byte, sig []byte) bool {
				return ed25519.Verify(publicKey, data, sig)
			},
		}, nil
	case payloadpb.KeyType_KeyTypeDHX25519:
		curve := ecdh.X25519()
		publicKey, err := curve.NewPublicKey(input.Data)
		if err != nil {
			return nil, err
		}
		return &ecdhPublicKey{
			KeyType:   input.KeyType,
			PublicKey: publicKey,
		}, nil
	}
	return nil, fmt.Errorf("invalid key type: %v", input.KeyType)
}
