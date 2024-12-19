package kr.jclab.jscp.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

object Hash {
    fun hash(data: ByteArray): ByteArray {
        val digest = SHA256Digest()
        val output = ByteArray(digest.digestSize)
        digest.update(data, 0, data.size)
        digest.doFinal(output, 0)
        return output
    }

    fun hkdf(key: ByteArray, salt: ByteArray?): Pair<ByteArray, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        val params = HKDFParameters(key, salt, null)
        hkdf.init(params)

        val okm = ByteArray(96)
        hkdf.generateBytes(okm, 0, okm.size)

        return Pair(
            okm.copyOfRange(0, 32),
            okm.copyOfRange(32, 64)
        )
    }
}