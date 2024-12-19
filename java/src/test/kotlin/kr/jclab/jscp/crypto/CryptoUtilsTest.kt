package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.CryptoAlgorithm
import kr.jclab.jscp.payload.EncryptedMessage
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.Arrays

class CryptoUtilsTest {
    @Test
    fun encryptAndDecrypt_withoutAAD() {
        val key = "0123456789abcdef0123456789abcdef".toByteArray()

        val plaintext = ByteArray(128 + 5)
        ProviderHolder.SECURE_RANDOM.nextBytes(plaintext)

        val encryptedMessage =
            CryptoUtils.encrypt(CryptoAlgorithm.CryptoAlgorithmAes, EncryptedMessage.newBuilder(), key, null, plaintext)

        val decrypted = CryptoUtils.decrypt(CryptoAlgorithm.CryptoAlgorithmAes, key, null, encryptedMessage)

        assertThat(decrypted).isEqualTo(plaintext)
    }

    @Test
    fun encryptAndDecrypt_withAAD() {
        val key = "0123456789abcdef0123456789abcdef".toByteArray()
        val authData = "test".toByteArray()

        val plaintext = ByteArray(128 + 5)
        ProviderHolder.SECURE_RANDOM.nextBytes(plaintext)

        val encryptedMessage = CryptoUtils.encrypt(
            CryptoAlgorithm.CryptoAlgorithmAes,
            EncryptedMessage.newBuilder(),
            key,
            authData,
            plaintext
        )

        val decrypted = CryptoUtils.decrypt(CryptoAlgorithm.CryptoAlgorithmAes, key, authData, encryptedMessage)

        assertThat(decrypted).isEqualTo(plaintext)
    }

    @Test
    fun aesGcmTestVectors() {
        val vectors = listOf(
            TestVector(
                key = "00000000000000000000000000000000",
                iv = "000000000000000000000000",
                plainText = "",
                adata = "",
                cipherText = "",
                tag = "58e2fccefa7e3061367f1d57a4e7455a"
            ),
            TestVector(
                key = "00000000000000000000000000000000",
                iv = "000000000000000000000000",
                plainText = "00000000000000000000000000000000",
                adata = "",
                cipherText = "0388dace60b6a392f328c2b971b2fe78",
                tag = "ab6e47d42cec13bdf53a67b21257bddf"
            ),
            TestVector(
                key = "feffe9928665731c6d6a8f9467308308",
                adata = "",
                iv = "cafebabefacedbaddecaf888",
                plainText = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                cipherText = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                tag = "4d5c2af327cd64a62cf35abd2ba6fab4",
            ),
            TestVector(
                key = "feffe9928665731c6d6a8f9467308308",
                adata = "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                iv = "cafebabefacedbaddecaf888",
                plainText = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                cipherText = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                tag = "5bc94fbc3221a5db94fae95ae7121a47",
            ),
        )

        for (vector in vectors) {
            val key = hexStringToByteArray(vector.key)
            val iv = hexStringToByteArray(vector.iv)
            val plainText = hexStringToByteArray(vector.plainText)
            val adata = hexStringToByteArray(vector.adata)
            val expectedCipherText = hexStringToByteArray(vector.cipherText)
            val expectedTag = hexStringToByteArray(vector.tag)

            val encryptedMessage = CryptoUtils.encrypt(
                CryptoAlgorithm.CryptoAlgorithmAes,
                EncryptedMessage.newBuilder()
                    .setNonce(ByteString.copyFrom(iv)),
                key,
                adata,
                plainText
            )
            val cipherTextWithTag = encryptedMessage.ciphertext.toByteArray()

            val actualCipherText = cipherTextWithTag.copyOf(cipherTextWithTag.size - 16)
            val actualTag = cipherTextWithTag.copyOfRange(cipherTextWithTag.size - 16, cipherTextWithTag.size)

            assertThat(actualCipherText).isEqualTo(expectedCipherText)
            assertThat(actualTag).isEqualTo(expectedTag)
        }
    }

    data class TestVector(
        val key: String,
        val iv: String,
        val plainText: String,
        val adata: String,
        val cipherText: String,
        val tag: String
    )

    fun hexStringToByteArray(s: String): ByteArray {
        val len = s.length
        val data = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            data[i / 2] = ((Character.digit(s[i], 16) shl 4)
                    + Character.digit(s[i + 1], 16)).toByte()
        }
        return data
    }
}