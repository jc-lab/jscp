package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.JcspPayload

interface CipherAlgorithm {
    fun getType(): JcspPayload.CipherAlgorithm
    fun seal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray
    fun open(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray
}