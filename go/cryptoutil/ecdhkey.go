package cryptoutil

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
)

type ecdhPrivateKey struct {
	KeyType    payloadpb.KeyType
	PrivateKey *ecdh.PrivateKey
}

func (k *ecdhPrivateKey) DhAgreement(publicKey OpPublicKey) ([]byte, error) {
	pubKey, ok := publicKey.(*ecdhPublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not suitable")
	}

	return k.PrivateKey.ECDH(pubKey.PublicKey)
}

func (k *ecdhPrivateKey) Sign(data []byte) ([]byte, error) {
	return nil, errors.New("not supported operation")
}

func (k *ecdhPrivateKey) ToPublic() (OpPublicKey, error) {
	return &ecdhPublicKey{
		KeyType:   k.KeyType,
		PublicKey: k.PrivateKey.PublicKey(),
	}, nil
}

type ecdhPublicKey struct {
	KeyType   payloadpb.KeyType
	PublicKey *ecdh.PublicKey
}

func (k *ecdhPublicKey) ToPublicKeyProto() (*payloadpb.PublicKey, error) {
	return &payloadpb.PublicKey{
		KeyType: k.KeyType,
		Data:    k.PublicKey.Bytes(),
	}, nil
}

func (k *ecdhPublicKey) Verify(data []byte, sig []byte) bool {
	return false
}
