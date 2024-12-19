package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.JcspPayload

object Registry {
    fun getCipherAlgorithm(algorithm: JcspPayload.CipherAlgorithm): CipherAlgorithm {
        return when (algorithm) {
            JcspPayload.CipherAlgorithm.CipherAesGcm -> AesGcmCipher()
            else -> throw IllegalArgumentException("Unknown cipher algorithm: $algorithm")
        }
    }

    fun getPublicAlgorithm(keyFormat: JcspPayload.KeyFormat, isDHKey: Boolean): PublicAlgorithm {
        return when (keyFormat) {
            JcspPayload.KeyFormat.KeyFormatEd25519 -> Ed25519Algorithm
            JcspPayload.KeyFormat.KeyFormatX25519 -> X25519Algorithm
//            JcspPayload.KeyFormat.KeyFormatX509Certificate -> X509Algorithm
            JcspPayload.KeyFormat.KeyFormatSubjectPublicKeyInfo -> ECCAlgorithm(if (isDHKey) KeyUsage.DH else KeyUsage.SIGNATURE)
            else -> throw IllegalArgumentException("Unknown key format: $keyFormat")
        }
    }

    fun getDHAlgorithm(algorithm: JcspPayload.DHAlgorithm): DHAlgorithm {
        return when (algorithm) {
            JcspPayload.DHAlgorithm.DHX25519 -> X25519Algorithm
            else -> throw IllegalArgumentException("Unknown DH algorithm: $algorithm")
        }
    }
}