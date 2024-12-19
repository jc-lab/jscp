package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.CryptoAlgorithm
import kr.jclab.jscp.payload.EncryptedMessage
import kr.jclab.jscp.payload.KeyType
import kr.jclab.jscp.payload.PublicKey
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.*

object CryptoUtils {
    fun hashSha256(data: ByteArray): ByteArray {
        val digest = SHA256Digest.newInstance()
        digest.update(data, 0, data.size)
        val out = ByteArray(digest.digestSize)
        digest.doFinal(out, 0)
        return out
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val params = HKDFParameters(ikm, salt, info)
        val output = ByteArray(length)
        val generator = HKDFBytesGenerator(SHA256Digest.newInstance())
        generator.init(params)
        generator.generateBytes(output, 0, output.size)
        return output
    }

    fun encrypt(algorithm: CryptoAlgorithm, builder: EncryptedMessage.Builder, key: ByteArray, authData: ByteArray?, plaintext: ByteArray): EncryptedMessage {
        val nonce = if (builder.nonce.isEmpty) {
            val out = ByteArray(12)
            ProviderHolder.SECURE_RANDOM.nextBytes(out)
            builder.setNonce(ByteString.copyFrom(out))
            out
        } else {
            builder.nonce.toByteArray()
        }

        val gcmBlockCipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        gcmBlockCipher.init(true, AEADParameters(KeyParameter(key), 16 * 8, nonce))

        val ciphertext = ByteArray(gcmBlockCipher.getOutputSize(plaintext.size))
        val l = gcmBlockCipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
        if (authData != null) {
            gcmBlockCipher.processAADBytes(authData, 0, authData.size)
        }
        gcmBlockCipher.doFinal(ciphertext, l)

        return builder
            .setCiphertext(ByteString.copyFrom(ciphertext))
            .build()
    }

    fun decrypt(algorithm: CryptoAlgorithm, key: ByteArray, authData: ByteArray?, message: EncryptedMessage): ByteArray {
        val gcmBlockCipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        gcmBlockCipher.init(false, AEADParameters(KeyParameter(key), 16 * 8, message.nonce.toByteArray()))

        val ciphertext = message.ciphertext.toByteArray()
        val plaintext = ByteArray(message.ciphertext.size())
        val l = gcmBlockCipher.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
        if (authData != null) {
            gcmBlockCipher.processAADBytes(authData, 0, authData.size)
        }
        val m = gcmBlockCipher.doFinal(plaintext, l)

        return Arrays.copyOf(plaintext, l + m)
    }

    fun generateKeyPair(keyType: KeyType): OpKeyPair {
        return when (keyType) {
            KeyType.KeyTypeDHX25519 -> generate25519KeyPair(KeyType.KeyTypeDHX25519, X25519KeyPairGenerator())
            KeyType.KeyTypeSignatureEd25519 -> generate25519KeyPair(KeyType.KeyTypeSignatureEd25519, Ed25519KeyPairGenerator())
            else -> {
                throw RuntimeException("unknown: ${keyType}")
            }
        }
    }

    fun unmarshal(publicKey: PublicKey): OpPublicKey {
        return when (publicKey.keyType) {
            KeyType.KeyTypeDHX25519 -> BcOpPublicKey.unmarshalX25519(publicKey.data.toByteArray())
            KeyType.KeyTypeSignatureEd25519 -> BcOpPublicKey.unmarshalEd25519(publicKey.data.toByteArray())
            else -> {
                throw RuntimeException("unknown: ${publicKey.keyType}")
            }
        }
    }

    fun generate25519KeyPair(
        keyType: KeyType,
        keyPairGenerator: AsymmetricCipherKeyPairGenerator
    ): OpKeyPair {
        keyPairGenerator.init(KeyGenerationParameters(ProviderHolder.SECURE_RANDOM, 256))
        val keyPair = keyPairGenerator.generateKeyPair()

        return OpKeyPair(
            privateKey = BcOpPrivateKey.from(keyType, keyPair.private),
            publicKey = BcOpPublicKey.from(keyType, keyPair.public),
        )
    }

    fun unmarshal25519KeyPair(
        keyType: KeyType,
        bytes: ByteArray,
        keyPairGenerator: AsymmetricCipherKeyPairGenerator,
    ): OpKeyPair {
        keyPairGenerator.init(KeyGenerationParameters(ProviderHolder.SECURE_RANDOM, 256))
        val keyPair = keyPairGenerator.generateKeyPair()

        return OpKeyPair(
            privateKey = BcOpPrivateKey.from(keyType, keyPair.private),
            publicKey = BcOpPublicKey.from(keyType, keyPair.public),
        )
    }

    fun encodeLongBE(input: Long): ByteArray {
        val out = ByteArray(8)
        ByteBuffer.wrap(out)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(input)
        return out
    }
}