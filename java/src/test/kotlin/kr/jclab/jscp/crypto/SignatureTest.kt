package kr.jclab.jscp.crypto

import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class SignatureTest {
    val signatureAlgorithm = ECCAlgorithm(KeyUsage.SIGNATURE)

    @ParameterizedTest
    @ValueSource(strings = ["P-256", "P-384", "P-521"])
    fun `should use correct signature algorithm for each curve`(curve: String) {
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
    fun `should fail when using signing key for DH`() {
        // given
        val (privateKey, _) = signatureAlgorithm.generateKeyPair("P-256")
        val (_, bobPublic) = ECCAlgorithm(KeyUsage.DH).generateKeyPair("P-256")

        // then
        assertThatThrownBy {
            privateKey.dh(bobPublic)
        }.isInstanceOf(IllegalStateException::class.java)
            .hasMessage("Not a DH key")
    }
}