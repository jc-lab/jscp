package cryptoutil

//
//func TestEd25519PublicKeyUnmarshal(t *testing.T) {
//	protoData := unmarshalPublicKeyProto(t, "086612208af53aba494c443b17613baab420882aeabaefbfd9d17bbc0fcbb05847702d35")
//	publicKey, err := ed25519Algorithm.UnmarshalPublicKey(protoData)
//	assert.NoError(t, err)
//	log.Println(publicKey)
//
//	data := []byte(strings.Repeat("HELLO", 100))
//	sig := decodeHex(t, "312e29d5270a5ae74b1a732f09f00423404ec9d7fee44b9a7af8fa640b9b9049ab7a300e063061955b3734e485b93641582bcab96c9e481ce59fe735debb8c04")
//	assert.True(t, publicKey.Verify(data, sig))
//}
//
//func TestX25519Ecdh(t *testing.T) {
//	curve := ecdh.X25519()
//
//	expectedShared := decodeHex(t, "7180d0ca0c08f67bf45e7596479ca74209861dec5de192dd6760fd530294881c")
//	pr1 := decodeEcdhPrivateKey(t, curve, decodeHex(t, "58b0d92621432e2d613d7922232417d983503c958a1309212ff16a5993b85654"))
//	pu1 := decodeEcdhPublicKey(t, curve, decodeHex(t, "9bb4d7b051808cebbcddd79603f633ad45a8318b1428f1e14dd7e7a42687184b"))
//	pr2 := decodeEcdhPrivateKey(t, curve, decodeHex(t, "e8ee7554cb4447334e96879fcb4b4b9329644be342bd0dbc5e82e03c60499e5d"))
//	pu2 := decodeEcdhPublicKey(t, curve, decodeHex(t, "bb9d5f3d6db83388b4b6b3188a430c4cb862c86a22087c24e414c937d1e7ff13"))
//
//	s1, err := pr1.ECDH(pu2)
//	assert.NoError(t, err)
//	s2, err := pr2.ECDH(pu1)
//	assert.NoError(t, err)
//
//	assert.Equal(t, s1, s2)
//	assert.Equal(t, expectedShared, s1)
//}
//
//func decodeHex(t *testing.T, hexString string) []byte {
//	encoded, err := hex.DecodeString(hexString)
//	if err != nil {
//		t.Fatal(err)
//	}
//	return encoded
//}
//
//func unmarshalPublicKeyProto(t *testing.T, hexString string) *payloadpb.PublicKey {
//	out := &payloadpb.PublicKey{}
//	if err := hexString.UnmarshalVT(decodeHex(t), out); err != nil {
//		t.Fatal(err)
//	}
//	return out
//}
//
//func decodeEcdhPrivateKey(t *testing.T, curve ecdh.Curve, input []byte) *ecdh.PrivateKey {
//	p, err := curve.NewPrivateKey(input)
//	if err != nil {
//		t.Fatal(err)
//	}
//	return p
//}
//
//func decodeEcdhPublicKey(t *testing.T, curve ecdh.Curve, input []byte) *ecdh.PublicKey {
//	p, err := curve.NewPublicKey(input)
//	if err != nil {
//		t.Fatal(err)
//	}
//	return p
//}
