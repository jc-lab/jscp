package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.JcspPayload
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

object Ed25519Algorithm : PublicAlgorithm {
    override fun getKeyFormat(): JcspPayload.KeyFormat = JcspPayload.KeyFormat.KeyFormatEd25519

    override fun unmarshalPublicKey(input: ByteArray): JscpPublicKey {
        return Ed25519PublicKey(Ed25519PublicKeyParameters(input, 0))
    }

    fun generate(): Pair<Ed25519PrivateKey, Ed25519PublicKey> {
        val generator = Ed25519KeyPairGenerator()
        generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val keyPair = generator.generateKeyPair()

        val privateKey = Ed25519PrivateKey(keyPair.private as Ed25519PrivateKeyParameters)
        val publicKey = Ed25519PublicKey(keyPair.public as Ed25519PublicKeyParameters)

        return Pair(privateKey, publicKey)
    }
}

class Ed25519PrivateKey(private val key: Ed25519PrivateKeyParameters) : SignaturePrivateKey {
    override fun isDHKey(): Boolean = false

    override fun isSignatureKey(): Boolean = true

    override fun algorithm(): PublicAlgorithm = Ed25519Algorithm

    override fun getPublic(): JscpPublicKey = getSignaturePublicKey()

    override fun getSignaturePublicKey(): SignaturePublicKey = Ed25519PublicKey(key.generatePublicKey())

    override fun sign(data: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, key)
        signer.update(data, 0, data.size)
        return signer.generateSignature()
    }
}

class Ed25519PublicKey(val key: Ed25519PublicKeyParameters) : SignaturePublicKey {
    override fun isDHKey(): Boolean = false

    override fun isSignatureKey(): Boolean = true

    override fun algorithm(): PublicAlgorithm = Ed25519Algorithm

    override fun verify(data: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, key)
        verifier.update(data, 0, data.size)
        return verifier.verifySignature(signature)
    }

    override fun marshalToProto(): JcspPayload.PublicKey = JcspPayload.PublicKey.newBuilder()
        .setFormat(JcspPayload.KeyFormat.KeyFormatEd25519)
        .setData(ByteString.copyFrom(key.encoded))
        .build()
}
