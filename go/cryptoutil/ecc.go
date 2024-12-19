package cryptoutil

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
	"github.com/pkg/errors"
)

// OIDs for public key algorithms
var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// OIDs for elliptic curves
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type curveDefine struct {
	Dsa elliptic.Curve
	Dh  ecdh.Curve
}

// Mapping of curve OIDs to curve implementations
var curveByOID = map[string]*curveDefine{
	oidNamedCurveP256.String(): &curveDefine{
		Dsa: elliptic.P256(),
		Dh:  ecdh.P256(),
	},

	oidNamedCurveP384.String(): &curveDefine{
		Dsa: elliptic.P384(),
		Dh:  ecdh.P384(),
	},

	oidNamedCurveP521.String(): &curveDefine{
		Dsa: elliptic.P521(),
		Dh:  ecdh.P521(),
	},
}

// SubjectPublicKeyInfo represents the ASN.1 structure of the same name
type SubjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type ECCAlgorithm struct {
	keyUsage KeyUsage
}

type ECCDHSpecificAlgorithm struct {
	ECCAlgorithm
	dhCurve ecdh.Curve
}

func (a *ECCDHSpecificAlgorithm) GetType() payloadpb.DHAlgorithm {
	return payloadpb.DHAlgorithm_DHECC
}

func (a *ECCDHSpecificAlgorithm) Generate() (*DHKeyPair, error) {
	privateKey, err := a.dhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	eccPrivateKey := NewECCPrivateKey(nil, privateKey, KeyUsageDH)

	return &DHKeyPair{
		Private: eccPrivateKey,
		Public:  eccPrivateKey.GetDHPublic(),
	}, nil
}

func (a *ECCDHSpecificAlgorithm) UnmarshalDHPublicKey(input []byte) (DHPublicKey, error) {
	return a.unmarshalPublicKey(input)
}

func (a *ECCAlgorithm) GetKeyFormat() payloadpb.KeyFormat {
	return payloadpb.KeyFormat_KeyFormatSubjectPublicKeyInfo
}

func (a *ECCAlgorithm) unmarshalPublicKey(input []byte) (*ECCPublicKey, error) {
	var spki SubjectPublicKeyInfo
	rest, err := asn1.Unmarshal(input, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing data after SubjectPublicKeyInfo")
	}

	if !spki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, errors.New("invalid ECC algorithm")
	}

	// ECDSA public key
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, namedCurveOID); err != nil {
		return nil, fmt.Errorf("failed to parse EC parameters: %w", err)
	}

	namedCurve := curveByOID[namedCurveOID.String()]
	if namedCurve == nil {
		return nil, fmt.Errorf("unsupported elliptic curve: %v", namedCurveOID)
	}

	x, y := elliptic.Unmarshal(namedCurve.Dsa, spki.PublicKey.Bytes)
	if x == nil {
		return nil, errors.New("failed to unmarshal EC point")
	}

	dsaKey := &ecdsa.PublicKey{
		Curve: namedCurve.Dsa,
		X:     x,
		Y:     y,
	}
	dhKey, err := namedCurve.Dh.NewPublicKey(spki.PublicKey.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create dh key")
	}

	instance := &ECCPublicKey{
		keyUsage: a.keyUsage,
		DsaKey:   dsaKey,
		DhKey:    dhKey,
	}
	return instance, nil
}

func (a *ECCAlgorithm) UnmarshalPublicKey(input []byte) (PublicKey, error) {
	return a.unmarshalPublicKey(input)
}

type ECCPublicKey struct {
	DsaKey   *ecdsa.PublicKey
	DhKey    *ecdh.PublicKey
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

func (k *ECCPublicKey) GetDHAlgorithm() DHAlgorithm {
	if k.DhKey == nil {
		return nil
	}
	return &ECCDHSpecificAlgorithm{
		dhCurve: k.DhKey.Curve(),
	}
}

func (k *ECCPublicKey) Verify(data []byte, signature []byte) (bool, error) {
	return ecdsa.VerifyASN1(k.DsaKey, Hash(data), signature), nil
}

func (k *ECCPublicKey) MarshalToProto() (*payloadpb.PublicKey, error) {
	var raw []byte
	var err error
	if k.keyUsage == KeyUsageSignature {
		raw, err = x509.MarshalPKIXPublicKey(k.DsaKey)
	} else if k.keyUsage == KeyUsageDH {
		raw, err = x509.MarshalPKIXPublicKey(k.DhKey)
	}
	if err != nil {
		return nil, err
	}
	return &payloadpb.PublicKey{
		Format: payloadpb.KeyFormat_KeyFormatSubjectPublicKeyInfo,
		Data:   raw,
	}, nil
}

func (k *ECCPublicKey) GetDHAlgorithmProto() payloadpb.DHAlgorithm {
	return payloadpb.DHAlgorithm_DHECC
}

func (k *ECCPublicKey) Marshal() []byte {
	p, _ := k.MarshalToProto()
	return p.Data
}

type ECCPrivateKey struct {
	DsaKey   *ecdsa.PrivateKey
	DhKey    *ecdh.PrivateKey
	keyUsage KeyUsage
}

func NewECCPrivateKey(ecdsaKey *ecdsa.PrivateKey, dhKey *ecdh.PrivateKey, keyUsage KeyUsage) *ECCPrivateKey {
	return &ECCPrivateKey{
		DsaKey:   ecdsaKey,
		DhKey:    dhKey,
		keyUsage: keyUsage,
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

func (k *ECCPrivateKey) GetDHAlgorithm() DHAlgorithm {
	if k.DhKey == nil {
		return nil
	}
	return &ECCDHSpecificAlgorithm{
		dhCurve: k.DhKey.Curve(),
	}
}

func (k *ECCPrivateKey) getPublic() *ECCPublicKey {
	p := &ECCPublicKey{
		keyUsage: k.keyUsage,
	}
	if k.DsaKey != nil {
		p.DsaKey = &k.DsaKey.PublicKey
	}
	if k.DhKey != nil {
		p.DhKey = k.DhKey.PublicKey()
	}
	return p
}

func (k *ECCPrivateKey) GetPublic() PublicKey {
	return k.getPublic()
}

func (k *ECCPrivateKey) GetSignaturePublicKey() SignaturePublicKey {
	return k.getPublic()
}

func (k *ECCPrivateKey) Sign(data []byte) ([]byte, error) {
	return k.DsaKey.Sign(rand.Reader, Hash(data), crypto.SHA256)
}

func (k *ECCPrivateKey) GetDHAlgorithmProto() payloadpb.DHAlgorithm {
	return payloadpb.DHAlgorithm_DHECC
}

func (k *ECCPrivateKey) GetDHPublic() DHPublicKey {
	return k.getPublic()
}

func (k *ECCPrivateKey) DH(peerKey DHPublicKey) ([]byte, error) {
	publicKey, ok := peerKey.(*ECCPublicKey)
	if !ok {
		return nil, errors.New("peerKey is not ECCDH")
	}
	return k.DhKey.ECDH(publicKey.DhKey)
}
