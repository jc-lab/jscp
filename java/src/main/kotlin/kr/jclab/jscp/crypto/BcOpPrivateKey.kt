package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.KeyType
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.lang.IllegalStateException

sealed class BcOpPrivateKey(
    val keyType: KeyType,
    private val keyParam: AsymmetricKeyParameter,
    val signable: Boolean,
    val keyAgreementable: Boolean,
) : OpPrivateKey {
    companion object {
        fun from(keyType: KeyType, keyParam: AsymmetricKeyParameter): BcOpPrivateKey {
            return when (keyType) {
                KeyType.KeyTypeSignatureEd25519 -> Ed25519(keyParam as Ed25519PrivateKeyParameters)
                KeyType.KeyTypeDHX25519 -> X25519(keyParam as X25519PrivateKeyParameters)
                else -> throw RuntimeException("unknown keyType: ${keyType}")
            }
        }
    }

    class Ed25519(private val keyParam: Ed25519PrivateKeyParameters) : BcOpPrivateKey(
        KeyType.KeyTypeSignatureEd25519,
        keyParam,
        true,
        false,
    ) {
        override fun dhAgreement(publicKey: OpPublicKey): ByteArray {
            throw IllegalStateException()
        }
    }

    class X25519(private val keyParam: X25519PrivateKeyParameters) : BcOpPrivateKey(
        KeyType.KeyTypeDHX25519,
        keyParam,
        false,
        true
    ) {
        override fun dhAgreement(publicKey: OpPublicKey): ByteArray {
            publicKey as BcOpPublicKey
            val buf = ByteArray(32)
            this.keyParam.generateSecret(publicKey.keyParam as X25519PublicKeyParameters, buf, 0)
            return buf
        }

    }

    override fun keyType(): KeyType = keyType

    override fun sign(message: ByteArray): ByteArray {
        if (!signable) {
            throw IllegalStateException()
        }
        TODO("Not yet implemented")
    }
}