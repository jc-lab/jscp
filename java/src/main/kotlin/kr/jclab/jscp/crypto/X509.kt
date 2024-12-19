package kr.jclab.jscp.crypto

import com.google.protobuf.ByteString
import kr.jclab.jscp.payload.JcspPayload
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec

//object X509Algorithm : PublicAlgorithm {
//    override fun getKeyFormat(): JcspPayload.KeyFormat = JcspPayload.KeyFormat.KeyFormatX509Certificate
//
//    override fun unmarshalPublicKey(input: ByteArray): JscpPublicKey {
//        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
//            .generateCertificate(input.inputStream()) as X509Certificate
//        return X509PublicKey(cert)
//    }
//}
//
//class X509PublicKey(val cert: X509Certificate) : SignaturePublicKey, DHPublicKey {
//    private val keyUsage: KeyUsage
//    private val publicKey: JscpPublicKey
//
//    init {
//        keyUsage = if (cert.keyUsage?.get(0) == true) { // digitalSignature
//            KeyUsage.SIGNATURE
//        } else {
//            KeyUsage.DH
//        }
//
//        val inputPublicKey = cert.publicKey
//        this.publicKey = when (inputPublicKey) {
//            is org.bouncycastle.jce.interfaces.ECPublicKey -> ECCPublicKey(inputPublicKey, keyUsage)
//            is ECPublicKey -> {
//                val kp = KeyFactory.getInstance("EC", SecurityHolder.PROVIDER)
//                ECCPublicKey(
//                    kp.generatePublic(ECPublicKeySpec(inputPublicKey.w, inputPublicKey.params)) as org.bouncycastle.jce.interfaces.ECPublicKey,
//                    keyUsage
//                )
//            }
//            else -> throw IllegalArgumentException("Unsupported key format: ${inputPublicKey}")
//        }
//    }
//
//    override fun isDHKey(): Boolean = keyUsage == KeyUsage.DH
//
//    override fun isSignatureKey(): Boolean = keyUsage == KeyUsage.SIGNATURE
//
//    override fun algorithm(): PublicAlgorithm = X509Algorithm
//
//    override fun verify(data: ByteArray, signature: ByteArray): Boolean {
//        val sig = Signature.getInstance("SHA256withECDSA")
//        sig.initVerify(cert)
//        sig.update(Hash.hash(data))
//        return sig.verify(signature)
//    }
//
//    override fun marshalToProto(): JcspPayload.PublicKey = JcspPayload.PublicKey.newBuilder()
//        .setFormat(JcspPayload.KeyFormat.KeyFormatX509Certificate)
//        .setData(ByteString.copyFrom(cert.encoded))
//        .build()
//
//    override fun getDHAlgorithm(): DHAlgorithm {
//        if (!isDHKey()) throw IllegalStateException("Not a DH key")
//        return ECCDHAlgorithm
//    }
//
//    override fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHECC
//
//    override fun marshal(): ByteArray = cert.encoded
//}
//
//class X509PrivateKey(
//    private val cert: X509Certificate,
//    private val privateKey: PrivateKey
//) : SignaturePrivateKey, DHPrivateKey {
//    private val keyUsage: KeyUsage
//
//    init {
//        keyUsage = if (cert.keyUsage?.get(0) == true) { // digitalSignature
//            KeyUsage.SIGNATURE
//        } else {
//            KeyUsage.DH
//        }
//    }
//
//    override fun isDHKey(): Boolean = keyUsage == KeyUsage.DH
//
//    override fun isSignatureKey(): Boolean = keyUsage == KeyUsage.SIGNATURE
//
//    override fun algorithm(): PublicAlgorithm = X509Algorithm
//
//    override fun getPublic(): JscpPublicKey = X509PublicKey(cert)
//
//    override fun getSignaturePublicKey(): SignaturePublicKey = X509PublicKey(cert)
//
//    override fun sign(data: ByteArray): ByteArray {
//        if (!isSignatureKey()) throw IllegalStateException("Not a signature key")
//        val sig = Signature.getInstance("SHA256withECDSA")
//        sig.initSign(privateKey)
//        sig.update(Hash.hash(data))
//        return sig.sign()
//    }
//
//    override fun getDHAlgorithm(): DHAlgorithm {
//        if (!isDHKey()) throw IllegalStateException("Not a DH key")
//        return when (privateKey) {
//            is ECPrivateKey -> getECDHAlgorithm(privateKey.params)
//            else -> throw IllegalStateException("Unsupported private key type")
//        }
//    }
//
//    override fun getDHAlgorithmProto(): JcspPayload.DHAlgorithm = JcspPayload.DHAlgorithm.DHECC
//
//    override fun getDHPublic(): DHPublicKey = X509PublicKey(cert)
//
//    override fun dh(peerKey: DHPublicKey): ByteArray {
//        if (!isDHKey()) throw IllegalStateException("Not a DH key")
//
//        when (privateKey) {
//            is ECPrivateKey -> {
//                val ecPrivateKey = privateKey as ECPrivateKey
//                val peerPublicKey = when (peerKey) {
//                    is X509PublicKey -> peerKey.cert.publicKey as ECPublicKey
//                    else -> throw IllegalArgumentException("Unsupported peer key type")
//                }
//
//                return performECDH(ecPrivateKey, peerPublicKey)
//            }
//            else -> throw IllegalStateException("Unsupported private key type")
//        }
//    }
//
//    private fun getECDHAlgorithm(params: ECParameterSpec): DHAlgorithm {
//        return ECDH(params)
//    }
//
//    private fun performECDH(privateKey: ECPrivateKey, publicKey: ECPublicKey): ByteArray {
//        val keyAgreement = javax.crypto.KeyAgreement.getInstance("ECDH")
//        keyAgreement.init(privateKey)
//        keyAgreement.doPhase(publicKey, true)
//        return keyAgreement.generateSecret()
//    }
//
//    companion object {
//        fun fromPKCS8(cert: X509Certificate, pkcs8Key: ByteArray): X509PrivateKey {
//            val keyFactory = java.security.KeyFactory.getInstance("EC")
//            val privateKey = keyFactory.generatePrivate(
//                java.security.spec.PKCS8EncodedKeySpec(pkcs8Key)
//            )
//            return X509PrivateKey(cert, privateKey)
//        }
//    }
//}
