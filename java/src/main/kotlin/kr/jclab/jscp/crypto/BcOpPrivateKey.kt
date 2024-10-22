package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.KeyType
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc8032.Ed25519
import java.lang.IllegalStateException

sealed class BcOpPrivateKey(
    val keyType: KeyType,
) : OpPrivateKey {
    companion object {
        fun from(keyType: KeyType, keyParam: AsymmetricKeyParameter): BcOpPrivateKey {
            return when (keyType) {
                KeyType.KeyTypeSignatureEd25519 -> BcEd25519(keyParam as Ed25519PrivateKeyParameters)
                KeyType.KeyTypeDHX25519 -> BcX25519(keyParam as X25519PrivateKeyParameters)
                else -> throw RuntimeException("unknown keyType: ${keyType}")
            }
        }
    }

    class BcEd25519(val keyParam: Ed25519PrivateKeyParameters) : BcOpPrivateKey(
        KeyType.KeyTypeSignatureEd25519,
    ) {
        override fun sign(message: ByteArray): ByteArray {
            val signature = ByteArray(Ed25519.SIGNATURE_SIZE)
            keyParam.sign(Ed25519.Algorithm.Ed25519, null, message, 0, message.size, signature, 0)
            return signature
        }
    }

    class BcX25519(val keyParam: X25519PrivateKeyParameters) : BcOpPrivateKey(
        KeyType.KeyTypeDHX25519,
    ) {
        override fun dhAgreement(publicKey: OpPublicKey): ByteArray {
            publicKey as BcOpPublicKey
            val buf = ByteArray(32)
            this.keyParam.generateSecret(publicKey.getAsymmetricKeyParameter() as X25519PublicKeyParameters, buf, 0)
            return buf
        }
    }

    override fun keyType(): KeyType = keyType

    override fun sign(message: ByteArray): ByteArray {
        throw IllegalStateException()
    }

    override fun dhAgreement(publicKey: OpPublicKey): ByteArray {
        throw IllegalStateException()
    }
}