package cryptoutil

import "github.com/jc-lab/jscp/go/payloadpb"

type KeyUsage int

const (
	KeyUsageDH        KeyUsage = 1
	KeyUsageSignature KeyUsage = 2
)

type CipherAlgorithm interface {
	GetType() payloadpb.CipherAlgorithm
	Seal(key []byte, nonce []byte, plaintext []byte, ad []byte) ([]byte, error)
	Open(key []byte, nonce []byte, ciphertext []byte, ad []byte) ([]byte, error)
}

type Key interface {
	IsDHKey() bool
	IsSignatureKey() bool
	Algorithm() PublicAlgorithm
}

type PublicKey interface {
	Key
	MarshalToProto() (*payloadpb.PublicKey, error)
}

type PublicAlgorithm interface {
	GetKeyFormat() payloadpb.KeyFormat
	UnmarshalPublicKey(input []byte) (PublicKey, error)
}

type SignaturePublicKey interface {
	PublicKey
	Verify(data []byte, signature []byte) (bool, error)
}

type SignaturePrivateKey interface {
	Key
	GetPublic() PublicKey
	GetSignaturePublicKey() SignaturePublicKey
	Sign(data []byte) ([]byte, error)
}

type DHAlgorithm interface {
	GetType() payloadpb.DHAlgorithm

	Generate() (*DHKeyPair, error)
	UnmarshalDHPublicKey(input []byte) (DHPublicKey, error)
}

type DHPublicKey interface {
	PublicKey
	Marshal() []byte
}

type DHPrivateKey interface {
	Key
	GetPublic() PublicKey
	
	DHAlgorithm() DHAlgorithm
	GetDHPublic() DHPublicKey
	DH(peerKey DHPublicKey) ([]byte, error)
}

type DHKeyPair struct {
	Public  DHPublicKey
	Private DHPrivateKey
}

type StaticPrivateKey interface {
	Key
	GetPublic() PublicKey
}
