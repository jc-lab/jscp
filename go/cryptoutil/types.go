package cryptoutil

import "github.com/jc-lab/jscp/go/payloadpb"

type CipherAlgorithm interface {
	GetType() payloadpb.CipherAlgorithm
	Seal(key []byte, nonce []byte, plaintext []byte, ad []byte) ([]byte, error)
	Open(key []byte, nonce []byte, ciphertext []byte, ad []byte) ([]byte, error)
}

type SignatureAlgorithm interface {
	GetType() payloadpb.SignatureAlgorithm
	UnmarshalPublicKey(input []byte) (SignaturePublicKey, error)
}

type SignaturePublicKey interface {
	Algorithm() SignatureAlgorithm
	Verify(data []byte, signature []byte) (bool, error)
	MarshalToProto() (*payloadpb.SignaturePublicKey, error)
}

type SignaturePrivateKey interface {
	Algorithm() SignatureAlgorithm
	GetPublic() SignaturePublicKey
	Sign(data []byte) ([]byte, error)
}

type DHAlgorithm interface {
	GetType() payloadpb.DHAlgorithm

	Generate() (*DHKeyPair, error)
	UnmarshalPublicKey(input []byte) (DHPublicKey, error)
}

type DHPublicKey interface {
	Algorithm() DHAlgorithm
	Marshal() []byte
}

type DHPrivateKey interface {
	Algorithm() DHAlgorithm
	DH(peerKey DHPublicKey) ([]byte, error)
}

type DHKeyPair struct {
	Public  DHPublicKey
	Private DHPrivateKey
}
