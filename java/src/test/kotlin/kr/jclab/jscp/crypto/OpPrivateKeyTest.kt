package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.KeyType
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Test

class OpPrivateKeyTest {
    @Test
    fun ed25519PublicKeyMarshalAndUnmarshal() {
        val keyPair = CryptoUtils.generateKeyPair(KeyType.KeyTypeSignatureEd25519)
        val signature = keyPair.privateKey.sign("HELLO".repeat(100).toByteArray())

        val marshalled1 = keyPair.publicKey.toPublicKeyProto()
        val unmarshaled = CryptoUtils.unmarshal(marshalled1)
        val marshalled2 = unmarshaled.toPublicKeyProto()

        assertThat(marshalled1).isEqualTo(marshalled2)

        System.out.println("HEX: ${Hex.toHexString(marshalled2.toByteArray())}")
        System.out.println("SIG: ${Hex.toHexString(signature)}")
    }

    @Test
    fun x25519MarshalAndUnmarshalAndEcdh() {
        val keyPairA = CryptoUtils.generateKeyPair(KeyType.KeyTypeDHX25519)
        val keyPairB = CryptoUtils.generateKeyPair(KeyType.KeyTypeDHX25519)

        val sharedA = keyPairA.privateKey.dhAgreement(keyPairB.publicKey)
        val sharedB = keyPairB.privateKey.dhAgreement(keyPairA.publicKey)

        assertThat(sharedA).isEqualTo(sharedB)

        val pr1 = (keyPairA.privateKey as BcOpPrivateKey.BcX25519).keyParam.encoded
        val pu1 = (keyPairA.publicKey as BcOpPublicKey.BcX25519).keyParam.encoded
        val pr2 = (keyPairB.privateKey as BcOpPrivateKey.BcX25519).keyParam.encoded
        val pu2 = (keyPairB.publicKey as BcOpPublicKey.BcX25519).keyParam.encoded

        System.out.println("SIG: ${Hex.toHexString(sharedA)}")
        System.out.println("pr1: ${Hex.toHexString(pr1)}")
        System.out.println("pu1: ${Hex.toHexString(pu1)}")
        System.out.println("pr2: ${Hex.toHexString(pr2)}")
        System.out.println("pu2: ${Hex.toHexString(pu2)}")
    }
}
