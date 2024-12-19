package kr.jclab.jscp.crypto

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class ECCKeyTest {
    val signatureAlgorithm = ECCAlgorithm(KeyUsage.SIGNATURE)
    val dhAlgorithm = ECCAlgorithm(KeyUsage.DH)

    @ParameterizedTest
    @ValueSource(strings = ["P-256", "P-384", "P-521"])
    fun `should sign and verify for different curves`(curve: String) {
        // given
        val (privateKey, publicKey) = signatureAlgorithm.generateKeyPair(curve)
        val data = "test data".toByteArray()

        // when
        val signature = privateKey.sign(data)
        val verified = publicKey.verify(data, signature)

        // then
        assertThat(verified).isTrue()
    }

    @Test
    fun `should fail verification with wrong data`() {
        // given
        val (privateKey, publicKey) = signatureAlgorithm.generateKeyPair("P-256")
        val data = "test data".toByteArray()
        val wrongData = "wrong data".toByteArray()

        // when
        val signature = privateKey.sign(data)
        val verified = publicKey.verify(wrongData, signature)

        // then
        assertThat(verified).isFalse()
    }

    @Test
    fun `should perform DH key exchange`() {
        // given
        val (alicePrivate, alicePublic) = dhAlgorithm.generateKeyPair("P-256")
        val (bobPrivate, bobPublic) = dhAlgorithm.generateKeyPair("P-256")

        // when
        val aliceShared = alicePrivate.dh(bobPublic)
        val bobShared = bobPrivate.dh(alicePublic)

        // then
        assertThat(aliceShared).isEqualTo(bobShared)
    }

    @Test
    fun `should properly handle key usage`() {
        // given
        val (signingKey, _) = signatureAlgorithm.generateKeyPair("P-256")
        val (dhKey, _) = dhAlgorithm.generateKeyPair("P-256")

        // then
        assertThat(signingKey.isSignatureKey()).isTrue()
        assertThat(signingKey.isDHKey()).isFalse()
        assertThat(dhKey.isDHKey()).isTrue()
        assertThat(dhKey.isSignatureKey()).isFalse()
    }
}