package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.JcspPayload
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

class AesGcmCipher : CipherAlgorithm {
    override fun getType(): JcspPayload.CipherAlgorithm = JcspPayload.CipherAlgorithm.CipherAesGcm

    override fun seal(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        ad: ByteArray
    ): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        val params = AEADParameters(KeyParameter(key), 128, nonce, ad)

        cipher.init(true, params)
        val output = ByteArray(cipher.getOutputSize(plaintext.size))

        val len = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
        cipher.doFinal(output, len)

        return output
    }

    override fun open(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        ad: ByteArray
    ): ByteArray {
        val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
        val params = AEADParameters(KeyParameter(key), 128, nonce, ad)

        cipher.init(false, params)
        val output = ByteArray(cipher.getOutputSize(ciphertext.size))

        val len = cipher.processBytes(ciphertext, 0, ciphertext.size, output, 0)
        cipher.doFinal(output, len)

        return output
    }
}