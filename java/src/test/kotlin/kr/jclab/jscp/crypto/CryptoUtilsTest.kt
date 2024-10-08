package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.CryptoAlgorithm
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class CryptoUtilsTest {
    @Test
    fun encryptAndDecrypt_withoutAAD() {
        val key = "0123456789abcdef0123456789abcdef".toByteArray()

        val plaintext = ByteArray(128+5)
        ProviderHolder.SECURE_RANDOM.nextBytes(plaintext)

        val encryptedMessage = CryptoUtils.encrypt(CryptoAlgorithm.CryptoAlgorithmAes, key, plaintext, null)

        val decrypted = CryptoUtils.decrypt(CryptoAlgorithm.CryptoAlgorithmAes, key, encryptedMessage, null)

        assertThat(decrypted).isEqualTo(plaintext)
    }

    @Test
    fun encryptAndDecrypt_withAAD() {
        val key = "0123456789abcdef0123456789abcdef".toByteArray()
        val authData = "test".toByteArray()

        val plaintext = ByteArray(128+5)
        ProviderHolder.SECURE_RANDOM.nextBytes(plaintext)

        val encryptedMessage = CryptoUtils.encrypt(CryptoAlgorithm.CryptoAlgorithmAes, key, plaintext, authData)

        val decrypted = CryptoUtils.decrypt(CryptoAlgorithm.CryptoAlgorithmAes, key, encryptedMessage, authData)

        assertThat(decrypted).isEqualTo(plaintext)
    }
}