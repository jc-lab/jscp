package cryptoutil

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

var aesGcmTestVectors = []struct {
	key        string
	iv         string
	plainText  string
	adata      string
	cipherText string
	tag        string
}{
	{
		key:        "00000000000000000000000000000000",
		iv:         "000000000000000000000000",
		plainText:  "",
		adata:      "",
		cipherText: "",
		tag:        "58e2fccefa7e3061367f1d57a4e7455a",
	},
	{
		key:        "00000000000000000000000000000000",
		iv:         "000000000000000000000000",
		plainText:  "00000000000000000000000000000000",
		adata:      "",
		cipherText: "0388dace60b6a392f328c2b971b2fe78",
		tag:        "ab6e47d42cec13bdf53a67b21257bddf",
	},
	{
		key:        "feffe9928665731c6d6a8f9467308308",
		adata:      "",
		iv:         "cafebabefacedbaddecaf888",
		plainText:  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
		cipherText: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
		tag:        "4d5c2af327cd64a62cf35abd2ba6fab4",
	},
	{
		key:        "feffe9928665731c6d6a8f9467308308",
		adata:      "feedfacedeadbeeffeedfacedeadbeefabaddad2",
		iv:         "cafebabefacedbaddecaf888",
		plainText:  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
		cipherText: "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
		tag:        "5bc94fbc3221a5db94fae95ae7121a47",
	},
}

func TestAESGCMWithEncrypt(t *testing.T) {
	c := &AesGcmCipher{}
	for index, v := range aesGcmTestVectors {
		t.Run(fmt.Sprintf("index %d", index), func(t *testing.T) {
			key, _ := hex.DecodeString(v.key)
			iv, _ := hex.DecodeString(v.iv)
			plainText, _ := hex.DecodeString(v.plainText)
			adata, _ := hex.DecodeString(v.adata)
			expectedCipherText, _ := hex.DecodeString(v.cipherText)
			expectedTag, _ := hex.DecodeString(v.tag)

			dest, err := c.Seal(key, iv, plainText, adata)
			assert.NoError(t, err)

			actualTag := dest[len(dest)-len(expectedTag):] // Assuming the tag is the last 16 bytes
			actualCipherText := dest[:len(dest)-len(expectedTag)]

			// Validate ciphertext and tag
			assert.Equal(t, expectedCipherText, actualCipherText)
			assert.Equal(t, expectedTag, actualTag)
		})
	}
}

func TestAESGCMWithDecrypt(t *testing.T) {
	c := &AesGcmCipher{}
	for index, v := range aesGcmTestVectors {
		t.Run(fmt.Sprintf("index %d", index), func(t *testing.T) {
			key, _ := hex.DecodeString(v.key)
			iv, _ := hex.DecodeString(v.iv)
			expectedPlainText, _ := hex.DecodeString(v.plainText)
			adata, _ := hex.DecodeString(v.adata)
			cipherText, _ := hex.DecodeString(v.cipherText)
			expectedTag, _ := hex.DecodeString(v.tag)

			plaintext, err := c.Open(key, iv, append(cipherText, expectedTag...), adata)
			assert.NoError(t, err)

			if plaintext == nil {
				plaintext = make([]byte, 0)
			}
			assert.Equal(t, expectedPlainText, plaintext)
		})
	}
}
