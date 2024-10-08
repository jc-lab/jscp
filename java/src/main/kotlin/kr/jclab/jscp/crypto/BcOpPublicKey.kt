package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.KeyType
import kr.jclab.jscp.payload.PublicKey
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

sealed class BcOpPublicKey(
    val keyType: KeyType,
    val keyParam: AsymmetricKeyParameter,
    val verifiable: Boolean,
    val keyAgreementable: Boolean,
) : OpPublicKey {
    companion object {
        fun from(keyType: KeyType, keyParam: AsymmetricKeyParameter): BcOpPublicKey {
            return when (keyType) {
                KeyType.KeyTypeSignatureEd25519 -> Ed25519(keyParam as Ed25519PublicKeyParameters)
                KeyType.KeyTypeDHX25519 -> X25519(keyParam as X25519PublicKeyParameters)
                else -> throw RuntimeException("unknown keyType: ${keyType}")
            }
        }

        fun unmarshalEd25519(bytes: ByteArray): Ed25519 = Ed25519(Ed25519PublicKeyParameters(bytes))
        fun unmarshalX25519(bytes: ByteArray): X25519 = X25519(X25519PublicKeyParameters(bytes))
    }

    class Ed25519(private val publicKeyParam: Ed25519PublicKeyParameters) : BcOpPublicKey(
        KeyType.KeyTypeSignatureEd25519,
        publicKeyParam,
        true,
        false,
    ) {
        override fun toPublicKeyProto(): PublicKey {
            return PublicKey.newBuilder()
                .setKeyType(keyType)
                .setData(ByteString.copyFrom(publicKeyParam.encoded))
                .build()
        }
    }

    class X25519(private val publicKeyParam: X25519PublicKeyParameters) : BcOpPublicKey(
        KeyType.KeyTypeDHX25519,
        publicKeyParam,
        false,
        true
    ) {
        override fun toPublicKeyProto(): PublicKey {
            return PublicKey.newBuilder()
                .setKeyType(keyType)
                .setData(ByteString.copyFrom(publicKeyParam.encoded))
                .build()
        }
    }

    override fun keyType(): KeyType = keyType
}