package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.JcspPayload
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom

object X25519Algorithm : DHAlgorithm {
    override fun getKeyFormat(): JcspPayload.KeyFormat = JcspPayload.KeyFormat.KeyFormatX25519

    override fun getType(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHX25519

    override fun generate(): DHKeyPair {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(SecureRandom()))
        val keyPair = generator.generateKeyPair()

        val privateKey = X25519PrivateKey(keyPair.private as X25519PrivateKeyParameters)
        val publicKey = X25519PublicKey(keyPair.public as X25519PublicKeyParameters)

        return DHKeyPair(publicKey, privateKey)
    }

    override fun unmarshalPublicKey(input: ByteArray): JscpPublicKey {
        return unmarshalDHPublicKey(input)
    }

    override fun unmarshalDHPublicKey(input: ByteArray): DHPublicKey {
        return X25519PublicKey(X25519PublicKeyParameters(input, 0))
    }
}

class X25519PrivateKey(private val key: X25519PrivateKeyParameters) : DHPrivateKey {
    override fun isDHKey(): Boolean = true

    override fun isSignatureKey(): Boolean = false

    override fun algorithm(): PublicAlgorithm = X25519Algorithm

    override fun getPublic(): JscpPublicKey = getDHPublic()

    override fun getDHAlgorithm(): DHAlgorithm = X25519Algorithm

    override fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHX25519

    override fun getDHPublic(): DHPublicKey = X25519PublicKey(key.generatePublicKey())

    override fun dh(peerKey: DHPublicKey): ByteArray {
        require(peerKey is X25519PublicKey) { "Peer key must be X25519PublicKey" }
        val sharedSecret = ByteArray(32)
        key.generateSecret(peerKey.key, sharedSecret, 0)
        return sharedSecret
    }
}

class X25519PublicKey(val key: X25519PublicKeyParameters) : DHPublicKey {
    override fun isDHKey(): Boolean = true

    override fun isSignatureKey(): Boolean = false

    override fun algorithm(): PublicAlgorithm = X25519Algorithm

    override fun getDHAlgorithm(): DHAlgorithm = X25519Algorithm

    override fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHX25519

    override fun marshal(): ByteArray = key.encoded

    override fun marshalToProto(): JcspPayload.PublicKey = JcspPayload.PublicKey.newBuilder()
        .setFormat(JcspPayload.KeyFormat.KeyFormatX25519)
        .setData(ByteString.copyFrom(key.encoded))
        .build()
}