package kr.jclab.jscp.crypto

import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.jce.ECNamedCurveTable
import org.junit.jupiter.api.Test


class ECCDHSpecificAlgorithmTest {
    val defaultAlgorithm = ECCDHSpecificAlgorithm(
        ECNamedCurveTable.getParameterSpec("P-256"),
    )

    @Test
    fun `should generate DH key pair`() {
        // when
        val keyPair = defaultAlgorithm.generate()

        // then
        assertThat(keyPair.private).isInstanceOf(DHPrivateKey::class.java)
        assertThat(keyPair.public).isInstanceOf(DHPublicKey::class.java)
        assertThat(keyPair.private.isDHKey()).isTrue()
        assertThat(keyPair.public.isDHKey()).isTrue()
    }

    @Test
    fun `should marshal and unmarshal DH public key`() {
        // given
        val keyPair = defaultAlgorithm.generate()

        // when
        val encoded = keyPair.public.marshal()
        val decoded = defaultAlgorithm.unmarshalDHPublicKey(encoded)

        // then
        assertThat(decoded.marshal()).isEqualTo(encoded)
    }

    @Test
    fun `should perform DH key exchange with generated keys`() {
        // given
        val aliceKeyPair = defaultAlgorithm.generate()
        val bobKeyPair = defaultAlgorithm.generate()

        // when
        val aliceShared = aliceKeyPair.private.dh(bobKeyPair.public)
        val bobShared = bobKeyPair.private.dh(aliceKeyPair.public)

        // then
        assertThat(aliceShared).isEqualTo(bobShared)
    }
}