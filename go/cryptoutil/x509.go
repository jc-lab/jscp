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

func getKeyUsageFromCert(cert *x509.Certificate) KeyUsage {
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		return KeyUsageSignature
	} else {
		return KeyUsageDH
	}
}

type X509Algorithm struct {
}

func (a *X509Algorithm) GetKeyFormat() payloadpb.KeyFormat {
	return payloadpb.KeyFormat_KeyFormatX509Certificate
}

func (a *X509Algorithm) UnmarshalPublicKey(input []byte) (PublicKey, error) {
	cert, err := x509.ParseCertificate(input)
	if err != nil {
		return nil, err
	}
	instance := &X509PublicKey{
		Cert:     cert,
		keyUsage: getKeyUsageFromCert(cert),
	}
	return instance, nil
}

type X509PublicKey struct {
	Cert     *x509.Certificate
	keyUsage KeyUsage
}

func (k *X509PublicKey) IsDHKey() bool {
	return k.keyUsage == KeyUsageDH
}

func (k *X509PublicKey) IsSignatureKey() bool {
	return k.keyUsage == KeyUsageSignature
}

func (k *X509PublicKey) Algorithm() PublicAlgorithm {
	return &x509Algorithm
}

func (k *X509PublicKey) Certificate() *x509.Certificate {
	return k.Cert
}

func (k *X509PublicKey) Verify(data []byte, signature []byte) (bool, error) {
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

func (k *X509PublicKey) MarshalToProto() (*payloadpb.PublicKey, error) {
	return &payloadpb.PublicKey{
		Format: k.Algorithm().GetKeyFormat(),
		Data:   k.Cert.Raw,
	}, nil
}

type X509PrivateKey struct {
	signer   crypto.Signer
	cert     *x509.Certificate
	keyUsage KeyUsage
}

func NewX509PrivateKey(cert *x509.Certificate, signer crypto.Signer) *X509PrivateKey {
	return &X509PrivateKey{
		signer:   signer,
		cert:     cert,
		keyUsage: getKeyUsageFromCert(cert),
	}
}

func (k *X509PrivateKey) IsDHKey() bool {
	return k.keyUsage == KeyUsageDH
}

func (k *X509PrivateKey) IsSignatureKey() bool {
	return k.keyUsage == KeyUsageSignature
}

func (k *X509PrivateKey) Algorithm() PublicAlgorithm {
	return &x509Algorithm
}

func (k *X509PrivateKey) GetPublic() SignaturePublicKey {
	return &X509PublicKey{
		Cert: k.cert,
	}
}

func (k *X509PrivateKey) Sign(data []byte) ([]byte, error) {
	return k.signer.Sign(rand.Reader, Hash(data), crypto.SHA256)
}
