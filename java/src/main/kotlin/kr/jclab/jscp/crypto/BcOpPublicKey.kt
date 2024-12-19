package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.KeyType
import kr.jclab.jscp.payload.PublicKey
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc8032.Ed25519

sealed class BcOpPublicKey(
    val keyType: KeyType,
) : OpPublicKey {
    companion object {
        fun from(keyType: KeyType, keyParam: AsymmetricKeyParameter): BcOpPublicKey {
            return when (keyType) {
                KeyType.KeyTypeSignatureEd25519 -> BcEd25519(keyParam as Ed25519PublicKeyParameters)
                KeyType.KeyTypeDHX25519 -> BcX25519(keyParam as X25519PublicKeyParameters)
                else -> throw RuntimeException("unknown keyType: ${keyType}")
            }
        }

        fun unmarshalEd25519(bytes: ByteArray): BcEd25519 = BcEd25519(Ed25519PublicKeyParameters(bytes))
        fun unmarshalX25519(bytes: ByteArray): BcX25519 = BcX25519(X25519PublicKeyParameters(bytes))
    }

    class BcEd25519(val keyParam: Ed25519PublicKeyParameters) : BcOpPublicKey(
        KeyType.KeyTypeSignatureEd25519,
    ) {
        override fun toPublicKeyProto(): PublicKey {
            return PublicKey.newBuilder()
                .setKeyType(keyType)
                .setData(ByteString.copyFrom(keyParam.encoded))
                .build()
        }

        override fun getAsymmetricKeyParameter(): AsymmetricKeyParameter = keyParam

        override fun verify(message: ByteArray, signature: ByteArray): Boolean {
            return keyParam.verify(Ed25519.Algorithm.Ed25519, null, message, 0, message.size, signature, 0)
        }
    }

    class BcX25519(val keyParam: X25519PublicKeyParameters) : BcOpPublicKey(
        KeyType.KeyTypeDHX25519,
    ) {
        override fun toPublicKeyProto(): PublicKey {
            return PublicKey.newBuilder()
                .setKeyType(keyType)
                .setData(ByteString.copyFrom(keyParam.encoded))
                .build()
        }

        override fun getAsymmetricKeyParameter(): AsymmetricKeyParameter = keyParam
    }

    override fun keyType(): KeyType = keyType

    abstract fun getAsymmetricKeyParameter(): AsymmetricKeyParameter

    override fun verify(message: ByteArray, signature: ByteArray): Boolean {
        throw IllegalStateException()
    }
}