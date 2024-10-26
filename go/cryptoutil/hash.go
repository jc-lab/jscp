package cryptoutil

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

// Hash computes the SHA256 hash of the input data
func Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// Hkdf generates a key using HKDF-SHA256
func Hkdf(key []byte, salt []byte) ([]byte, []byte) {
	hkdfReader := hkdf.New(sha256.New, key, salt, nil)
	out := make([]byte, 32*2)
	_, _ = io.ReadFull(hkdfReader, out)
	return out[0:32], out[32:64]
}
