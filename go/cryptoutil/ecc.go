package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
)

var eccAlgorithm ECCAlgorithm

type ECCAlgorithm struct {
}

func (a *ECCAlgorithm) GetKeyFormat() payloadpb.KeyFormat {
	return payloadpb.KeyFormat_KeyFormatSubjectPublicKeyInfo
}

func (a *ECCAlgorithm) UnmarshalPublicKey(input []byte) (PublicKey, error) {
	cert, err := x509.ParseCertificate(input)
	if err != nil {
		return nil, err
	}
	instance := &ECCPublicKey{
		Cert:     cert,
		keyUsage: getKeyUsageFromCert(cert),
	}
	return instance, nil
}

type ECCPublicKey struct {
	Cert     *x509.Certificate
	keyUsage KeyUsage
}

func (k *ECCPublicKey) IsDHKey() bool {
	return k.keyUsage == KeyUsageDH
}

func (k *ECCPublicKey) IsSignatureKey() bool {
	return k.keyUsage == KeyUsageSignature
}

func (k *ECCPublicKey) Algorithm() PublicAlgorithm {
	return &x509Algorithm
}

func (k *ECCPublicKey) Certificate() *x509.Certificate {
	return k.Cert
}

func (k *ECCPublicKey) Verify(data []byte, signature []byte) (bool, error) {
	pubKey := k.Cert.PublicKey
	switch typed := pubKey.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(typed, data, signature), nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(typed, Hash(data), signature), nil
	default:
		return false, fmt.Errorf("not supported public Key: %+v", typed)
	}
}

func (k *ECCPublicKey) MarshalToProto() (*payloadpb.PublicKey, error) {
	return &payloadpb.PublicKey{
		Format: k.Algorithm().GetKeyFormat(),
		Data:   k.Cert.Raw,
	}, nil
}

type ECCPrivateKey struct {
	signer   crypto.Signer
	cert     *x509.Certificate
	keyUsage KeyUsage
}

func NewECCPrivateKey(cert *x509.Certificate, signer crypto.Signer) *ECCPrivateKey {
	return &ECCPrivateKey{
		signer:   signer,
		cert:     cert,
		keyUsage: getKeyUsageFromCert(cert),
	}
}

func (k *ECCPrivateKey) IsDHKey() bool {
	return k.keyUsage == KeyUsageDH
}

func (k *ECCPrivateKey) IsSignatureKey() bool {
	return k.keyUsage == KeyUsageSignature
}

func (k *ECCPrivateKey) Algorithm() PublicAlgorithm {
	return &x509Algorithm
}

func (k *ECCPrivateKey) GetPublic() SignaturePublicKey {
	return &ECCPublicKey{
		Cert: k.cert,
	}
}

func (k *ECCPrivateKey) Sign(data []byte) ([]byte, error) {
	return k.signer.Sign(rand.Reader, Hash(data), crypto.SHA256)
}
