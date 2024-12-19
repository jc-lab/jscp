package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.JcspPayload
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

class ECCAlgorithm(
    val keyUsage: KeyUsage,
) : PublicAlgorithm {
    override fun getKeyFormat(): JcspPayload.KeyFormat =
        JcspPayload.KeyFormat.KeyFormatSubjectPublicKeyInfo

    override fun unmarshalPublicKey(input: ByteArray): JscpPublicKey {
        val keyFactory = KeyFactory.getInstance("EC", SecurityHolder.PROVIDER)
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(input))
        return ECCPublicKey(publicKey as ECPublicKey, keyUsage)
    }

    fun unmarshalPrivateKey(input: ByteArray): ECCPrivateKey {
        val keyFactory = KeyFactory.getInstance("EC", SecurityHolder.PROVIDER)
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(input))
        return ECCPrivateKey(privateKey as ECPrivateKey, keyUsage)
    }

    fun generateKeyPair(curve: String = "P-256"): Pair<ECCPrivateKey, ECCPublicKey> {
        val ecSpec = ECNamedCurveTable.getParameterSpec(curve)
        val keyPairGenerator = KeyPairGenerator.getInstance("EC", SecurityHolder.PROVIDER)
        keyPairGenerator.initialize(ecSpec)

        val keyPair = keyPairGenerator.generateKeyPair()
        return Pair(
            ECCPrivateKey(keyPair.private as ECPrivateKey, keyUsage),
            ECCPublicKey(keyPair.public as ECPublicKey, keyUsage)
        )
    }
}

class ECCPublicKey(
    val key: ECPublicKey,
    private val keyUsage: KeyUsage
) : SignaturePublicKey, DHPublicKey {

    override fun isDHKey(): Boolean = keyUsage == KeyUsage.DH

    override fun isSignatureKey(): Boolean = keyUsage == KeyUsage.SIGNATURE

    override fun algorithm(): PublicAlgorithm = ECCAlgorithm(keyUsage)

    override fun verify(data: ByteArray, signature: ByteArray): Boolean {
        if (!isSignatureKey()) throw IllegalStateException("Not a signature key")
        val sig = Signature.getInstance("SHA256withECDSA", SecurityHolder.PROVIDER)
        sig.initVerify(key)
        sig.update(data)
        return sig.verify(signature)
    }

    override fun getDHAlgorithm(): DHAlgorithm = ECCDHSpecificAlgorithm(key.parameters)

    override fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHECC

    override fun marshal(): ByteArray = key.encoded

    override fun marshalToProto(): JcspPayload.PublicKey = JcspPayload.PublicKey.newBuilder()
        .setFormat(JcspPayload.KeyFormat.KeyFormatSubjectPublicKeyInfo)
        .setData(ByteString.copyFrom(key.encoded))
        .build()
}

class ECCPrivateKey(
    internal val key: ECPrivateKey,
    private val keyUsage: KeyUsage
) : SignaturePrivateKey, DHPrivateKey {

    override fun isDHKey(): Boolean = keyUsage == KeyUsage.DH

    override fun isSignatureKey(): Boolean = keyUsage == KeyUsage.SIGNATURE

    override fun algorithm(): PublicAlgorithm = ECCAlgorithm(keyUsage)

    override fun getPublic(): JscpPublicKey {
        val keyFactory = KeyFactory.getInstance("EC", SecurityHolder.PROVIDER)
        val Q = key.parameters.g.multiply(key.d)
        val publicKey = keyFactory.generatePublic(ECPublicKeySpec(Q, key.parameters))
        return ECCPublicKey(publicKey as ECPublicKey, keyUsage)
    }

    override fun getSignaturePublicKey(): SignaturePublicKey =
        getPublic() as SignaturePublicKey

    override fun sign(data: ByteArray): ByteArray {
        if (!isSignatureKey()) throw IllegalStateException("Not a signature key")
        val sigAlgorithm = getSignatureAlgorithm(key.parameters)
        val sig = Signature.getInstance("SHA256withECDSA", SecurityHolder.PROVIDER)
        sig.initSign(key)
        sig.update(data)
        return sig.sign()
    }

    override fun getDHAlgorithm(): DHAlgorithm = ECCDHSpecificAlgorithm(key.parameters)

    override fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHECC

    override fun getDHPublic(): DHPublicKey = getPublic() as DHPublicKey

    override fun dh(peerKey: DHPublicKey): ByteArray {
        if (!isDHKey()) throw IllegalStateException("Not a DH key")
        require(peerKey is ECCPublicKey) { "Peer key must be ECCPublicKey" }

        val keyAgreement = KeyAgreement.getInstance("ECDH", SecurityHolder.PROVIDER)
        keyAgreement.init(key)
        keyAgreement.doPhase(peerKey.key, true)
        return keyAgreement.generateSecret()
    }
}

class ECCDHSpecificAlgorithm(
    val ecParameterSpec: ECParameterSpec,
) : DHAlgorithm {
    override fun getType(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHECC

    override fun getKeyFormat(): JcspPayload.KeyFormat =
        JcspPayload.KeyFormat.KeyFormatSubjectPublicKeyInfo

    override fun generate(): DHKeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC", SecurityHolder.PROVIDER)
        keyPairGenerator.initialize(ecParameterSpec)
        val keyPair = keyPairGenerator.generateKeyPair()
        val privateKey = ECCPrivateKey(keyPair.private as ECPrivateKey, KeyUsage.DH)
        val publicKey = ECCPublicKey(keyPair.public as ECPublicKey, KeyUsage.DH)
        return DHKeyPair(publicKey, privateKey)
    }

    override fun unmarshalDHPublicKey(input: ByteArray): DHPublicKey {
        val keyFactory = KeyFactory.getInstance("EC", SecurityHolder.PROVIDER)
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(input))
        return ECCPublicKey(publicKey as ECPublicKey, KeyUsage.DH)
    }

    override fun unmarshalPublicKey(input: ByteArray): JscpPublicKey =
        unmarshalDHPublicKey(input)
}

private fun getSignatureAlgorithm(ecParameterSpec: ECParameterSpec): String {
    return when (ecParameterSpec.curve.fieldSize) {
        256 -> "SHA256withECDSA"
        384 -> "SHA384withECDSA"
        521 -> "SHA512withECDSA"
        else -> throw IllegalArgumentException("Unsupported curve: ${ecParameterSpec}")
    }
}