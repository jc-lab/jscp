package cryptoutil

import (
	"crypto"
	"crypto/rand"
	"errors"
	"github.com/jc-lab/jscp/go/payloadpb"
)

type cryptoPrivateKey struct {
	KeyType    payloadpb.KeyType
	PrivateKey crypto.Signer
}

func (k *cryptoPrivateKey) DhAgreement(publicKey OpPublicKey) ([]byte, error) {
	return nil, errors.New("not supported operation")
}

func (k *cryptoPrivateKey) Sign(data []byte) ([]byte, error) {
	return k.PrivateKey.Sign(rand.Reader, data, nil)
}

func (k *cryptoPrivateKey) ToPublic() (OpPublicKey, error) {
	return &cryptoPublicKey{
		KeyType:   k.KeyType,
		PublicKey: k.PrivateKey.Public(),
	}, nil
}

type cryptoPublicKey struct {
	KeyType   payloadpb.KeyType
	PublicKey crypto.PublicKey
	Bytes     []byte
	verify    func(data []byte, sig []byte) bool
}

func (k *cryptoPublicKey) ToPublicKeyProto() (*payloadpb.PublicKey, error) {
	return &payloadpb.PublicKey{
		KeyType: k.KeyType,
		Data:    k.Bytes,
	}, nil
}

func (k *cryptoPublicKey) Verify(data []byte, sig []byte) bool {
	return k.verify(data, sig)
}
