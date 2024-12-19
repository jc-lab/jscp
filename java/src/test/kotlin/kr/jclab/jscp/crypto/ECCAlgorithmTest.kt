package kr.jclab.jscp.crypto

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class ECCAlgorithmTest {
    @ParameterizedTest
    @ValueSource(strings = ["P-256", "P-384", "P-521"])
    fun `should generate key pair for different curves`(curve: String) {
        // when
        val (privateKey, publicKey) = ECCAlgorithm(KeyUsage.SIGNATURE).generateKeyPair(curve)

        // then
        assertThat(privateKey).isInstanceOf(ECCPrivateKey::class.java)
        assertThat(publicKey).isInstanceOf(ECCPublicKey::class.java)
    }

    @Test
    fun `should marshal and unmarshal public key`() {
        // given
        val (_, publicKey) = ECCAlgorithm(KeyUsage.SIGNATURE).generateKeyPair("P-256")

        // when
        val encoded = publicKey.marshal()
        val decoded = ECCAlgorithm(KeyUsage.SIGNATURE).unmarshalPublicKey(encoded)

        // then
        assertThat(decoded).isInstanceOf(ECCPublicKey::class.java)
        assertThat((decoded as ECCPublicKey).marshal()).isEqualTo(encoded)
    }

    @Test
    fun `should marshal and unmarshal private key`() {
        // given
        val (privateKey, _) = ECCAlgorithm(KeyUsage.SIGNATURE).generateKeyPair("P-256")

        // when
        val encoded = privateKey.key.encoded
        val decoded = ECCAlgorithm(KeyUsage.SIGNATURE).unmarshalPrivateKey(encoded)

        // then
        assertThat(decoded).isInstanceOf(ECCPrivateKey::class.java)
        assertThat(decoded.key.encoded).isEqualTo(encoded)
    }
}

