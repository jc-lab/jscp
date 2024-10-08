package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.KeyType
import kr.jclab.jscp.payload.PublicKey

class OpKeyPair(
    val privateKey: OpPrivateKey,
    val publicKey: OpPublicKey,
) : OpPrivateKey, OpPublicKey {
    override fun keyType(): KeyType {
        return privateKey.keyType()
    }

    override fun toPublicKeyProto(): PublicKey = publicKey.toPublicKeyProto()

    override fun sign(message: ByteArray): ByteArray = privateKey.sign(message)

    override fun dhAgreement(publicKey: OpPublicKey): ByteArray = privateKey.dhAgreement(publicKey)
}