package kr.jclab.jscp.crypto

interface OpPrivateKey : OpKey {
    fun sign(message: ByteArray): ByteArray
    fun dhAgreement(publicKey: OpPublicKey): ByteArray
}