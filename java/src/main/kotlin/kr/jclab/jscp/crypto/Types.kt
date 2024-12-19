package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.JcspPayload

interface JscpKey {
    fun isDHKey(): Boolean
    fun isSignatureKey(): Boolean
    fun algorithm(): PublicAlgorithm
}

interface JscpPublicKey : JscpKey {
    fun marshalToProto(): JcspPayload.PublicKey
}

interface JscpPrivateKey : JscpKey {
    fun getPublic(): JscpPublicKey
}

interface PublicAlgorithm {
    fun getKeyFormat(): JcspPayload.KeyFormat
    fun unmarshalPublicKey(input: ByteArray): JscpPublicKey
}

interface SignaturePublicKey : JscpPublicKey {
    fun verify(data: ByteArray, signature: ByteArray): Boolean
}

interface SignaturePrivateKey : JscpPrivateKey {
    fun getSignaturePublicKey(): SignaturePublicKey
    fun sign(data: ByteArray): ByteArray
}

interface DHAlgorithm : PublicAlgorithm {
    fun getType(): JcspPayload.DHAlgorithm
    fun generate(): DHKeyPair
    fun unmarshalDHPublicKey(input: ByteArray): DHPublicKey
}

interface DHPublicKey : JscpPublicKey {
    fun getDHAlgorithm(): DHAlgorithm
    fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm
    fun marshal(): ByteArray
}

interface DHPrivateKey : JscpPrivateKey {
    fun getDHAlgorithm(): DHAlgorithm
    fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm
    fun getDHPublic(): DHPublicKey
    fun dh(peerKey: DHPublicKey): ByteArray
}

data class DHKeyPair(
    val public: DHPublicKey,
    val private: DHPrivateKey
)
