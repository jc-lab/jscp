package cryptoutil

import (
	"fmt"
	"github.com/jc-lab/jscp/go/payloadpb"
)

func GetCipherAlgorithm(algorithm payloadpb.CipherAlgorithm) (CipherAlgorithm, error) {
	switch algorithm {
	case payloadpb.CipherAlgorithm_CipherAesGcm:
		return &AesGcmCipher{}, nil
	default:
		return nil, fmt.Errorf("invalid algorithm: %v", algorithm)
	}
}

func GetSignatureAlgorithm(algorithm payloadpb.SignatureAlgorithm) (SignatureAlgorithm, error) {
	switch algorithm {
	case payloadpb.SignatureAlgorithm_SignatureEd25519:
		return &ed25519Algorithm, nil
	case payloadpb.SignatureAlgorithm_SignatureX509:
		return &x509Algorithm, nil
	default:
		return nil, fmt.Errorf("invalid algorithm: %v", algorithm)
	}
}

func GetDHAlgorithm(algorithm payloadpb.DHAlgorithm) (DHAlgorithm, error) {
	switch algorithm {
	case payloadpb.DHAlgorithm_DHX25519:
		return &x25519Algorithm, nil
	default:
		return nil, fmt.Errorf("invalid algorithm: %v", algorithm)
	}
}
