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

func GetPublicAlgorithm(keyFormat payloadpb.KeyFormat) (PublicAlgorithm, error) {
	switch keyFormat {
	case payloadpb.KeyFormat_KeyFormatEd25519:
		return &ed25519Algorithm, nil
	case payloadpb.KeyFormat_KeyFormatX509Certificate:
		return &x509Algorithm, nil
	case payloadpb.KeyFormat_KeyFormatX25519:
		return &x25519Algorithm, nil
	default:
		return nil, fmt.Errorf("invalid key format: %v", keyFormat)
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
