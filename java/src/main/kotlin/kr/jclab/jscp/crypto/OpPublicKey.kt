package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.PublicKey

interface OpPublicKey : OpKey {
    fun toPublicKeyProto(): PublicKey
    fun verify(message: ByteArray, signature: ByteArray): Boolean
}