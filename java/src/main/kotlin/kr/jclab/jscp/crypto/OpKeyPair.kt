package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.KeyType
import kr.jclab.jscp.payload.PublicKey

class OpKeyPair(
    val privateKey: OpPrivateKey,
    val publicKey: OpPublicKey,
) {
    fun keyType(): KeyType {
        return privateKey.keyType()
    }
}