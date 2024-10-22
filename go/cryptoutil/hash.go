package cryptoutil

import (
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
	"io"
)

// HashSha256 computes the SHA256 hash of the input data
func HashSha256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HkdfSha256 generates a key using HKDF-SHA256
func HkdfSha256(ikm, salt, info []byte, length int) []byte {
	hkdfReader := hkdf.New(sha256.New, ikm, salt, info)
	key := make([]byte, length)
	_, _ = io.ReadFull(hkdfReader, key)
	return key
}
