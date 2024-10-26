package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
)

var x509Algorithm X509Algorithm

type X509Algorithm struct {
}

func (a *X509Algorithm) GetType() payloadpb.SignatureAlgorithm {
	return payloadpb.SignatureAlgorithm_SignatureX509
}

func (a *X509Algorithm) UnmarshalPublicKey(input []byte) (SignaturePublicKey, error) {
	cert, err := x509.ParseCertificate(input)
	if err != nil {
		return nil, err
	}
	instance := &X509PublicKey{
		cert: cert,
	}
	return instance, nil
}

type X509PublicKey struct {
	cert *x509.Certificate
}

func (k *X509PublicKey) Algorithm() SignatureAlgorithm {
	return &x509Algorithm
}

func (k *X509PublicKey) Certificate() *x509.Certificate {
	return k.cert
}

func (k *X509PublicKey) Verify(data []byte, signature []byte) (bool, error) {
	pubKey := k.cert.PublicKey
	switch typed := pubKey.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(typed, data, signature), nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(typed, Hash(data), signature), nil
	default:
		return false, fmt.Errorf("not supported public key: %+v", typed)
	}
}

func (k *X509PublicKey) MarshalToProto() (*payloadpb.SignaturePublicKey, error) {
	return &payloadpb.SignaturePublicKey{
		Algorithm: k.Algorithm().GetType(),
		Data:      k.cert.Raw,
	}, nil
}

type X509PrivateKey struct {
	signer crypto.Signer
	cert   *x509.Certificate
}

func NewX509PrivateKey(cert *x509.Certificate, signer crypto.Signer) *X509PrivateKey {
	return &X509PrivateKey{
		signer: signer,
		cert:   cert,
	}
}

func (k *X509PrivateKey) Algorithm() SignatureAlgorithm {
	return &x509Algorithm
}

func (k *X509PrivateKey) GetPublic() SignaturePublicKey {
	return &X509PublicKey{
		cert: k.cert,
	}
}

func (k *X509PrivateKey) Sign(data []byte) ([]byte, error) {
	return k.signer.Sign(rand.Reader, Hash(data), crypto.SHA256)
}
