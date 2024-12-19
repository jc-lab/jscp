package cryptoutil

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHkdf(t *testing.T) {
	key, _ := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	salt, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F")
	expected1, _ := hex.DecodeString("c123697db89a6178c4c82fc7109c04b092253f1194aac2ea0bbf0becfd9cf014")
	expected2, _ := hex.DecodeString("dc9b865ddb0ad537996a627e72c966bb5439cfa142dffe3f0b2aa8969eb58672")
	got1, got2 := Hkdf(key, salt)

	assert.Equal(t, expected1, got1)
	assert.Equal(t, expected2, got2)
}
