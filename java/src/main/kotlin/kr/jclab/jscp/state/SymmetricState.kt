package kr.jclab.jscp.state

import kr.jclab.jscp.crypto.CipherAlgorithm
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.security.MessageDigest

open class SymmetricState {
    private var ck: ByteArray = ByteArray(0)
    private var h: ByteArray = ByteArray(0)
    private var cs: CipherState? = null

    open fun mixHash(data: ByteArray) {
        val digest = MessageDigest.getInstance("SHA-256")
        h = digest.digest(h + data)
    }

    open fun mixKey(cipher: CipherAlgorithm, key: ByteArray) {
        val (newCk, temp) = hkdf(key, ck)
        ck = newCk
        cs = CipherState(cipher, temp)
    }

    fun encryptWithAd(plaintext: ByteArray, ad: ByteArray): ByteArray {
        val state = cs ?: throw IllegalStateException("No cipher state")
        val ciphertext = state.cipher.seal(state.key, state.nonce.bytes, plaintext, ad)
        state.nonce.increment()
        return ciphertext
    }

    fun encryptAndMixHash(plaintext: ByteArray, mustSecret: Boolean): ByteArray {
        val ciphertext = if (cs != null) {
            encryptWithAd(plaintext, h)
        } else {
            if (mustSecret) throw IllegalStateException("Must be secret")
            plaintext
        }
        mixHash(ciphertext)
        return ciphertext
    }

    fun decryptWithAd(ciphertext: ByteArray, ad: ByteArray): ByteArray {
        val state = cs ?: throw IllegalStateException("No cipher state")
        val plaintext = state.cipher.open(state.key, state.nonce.bytes, ciphertext, ad)
        state.nonce.increment()
        return plaintext
    }

    fun mixHashAndDecrypt(ciphertext: ByteArray): ByteArray {
        val plaintext = if (cs != null) {
            decryptWithAd(ciphertext, h)
        } else {
            ciphertext
        }
        mixHash(ciphertext)
        return plaintext
    }

    private fun hkdf(ikm: ByteArray, salt: ByteArray): Pair<ByteArray, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        val params = HKDFParameters(ikm, salt, null)
        hkdf.init(params)

        val okm = ByteArray(96)
        hkdf.generateBytes(okm, 0, okm.size)

        return Pair(
            okm.copyOfRange(0, 32),
            okm.copyOfRange(32, 64)
        )
    }
}