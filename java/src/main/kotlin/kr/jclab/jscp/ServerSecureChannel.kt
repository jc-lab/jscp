package kr.jclab.jscp

import com.google.protobuf.ByteString
import kr.jclab.jscp.crypto.CryptoUtils
import kr.jclab.jscp.payload.*

open class ServerSecureChannel(
    writer: Writer,
) : SecureChannel(
    writer
) {
    private var clientHello: ClientHello? = null
    private var signedClientHello: ClientHelloSigned? = null

    open fun onClientHello(clientHello: ClientHello) {}
    open fun buildServerHello(
        serverHelloSignedBuilder: ServerHelloSigned.Builder,
        encryptedServerHelloBuilder: EncryptedServerHello.Builder,
    ) {}

    override fun startHandshake() {}

    override fun onMessage(payload: Payload) {
        when {
            payload.hasClientHello() -> {
                if (this.clientHello != null) {
                    throw IllegalProtocolException()
                }
                val clientHello = ClientHello.parseFrom(payload.clientHello)
                val clientHelloHash = CryptoUtils.hashSha256(payload.clientHello.toByteArray())
                this.clientHello = clientHello
                this.clientHelloHash = clientHelloHash

                val signedClientHello = ClientHelloSigned.parseFrom(clientHello.signed)
                this.signedClientHello = signedClientHello

                val localEphemeralKey = CryptoUtils.generateKeyPair(signedClientHello.ephemeralKey.keyType)
                this.localEphemeralKey = localEphemeralKey

                val remoteEphemeralKey = CryptoUtils.unmarshal(signedClientHello.ephemeralKey)
                this.remoteEphemeralKey = remoteEphemeralKey
                val ephemeralMasterKey = localEphemeralKey.privateKey.dhAgreement(remoteEphemeralKey)
                this.ephemeralMasterKey = ephemeralMasterKey

                onClientHello(clientHello)

                val serverHelloSignedBuilder = ServerHelloSigned.newBuilder()
                    .setEphemeralKey(localEphemeralKey.toPublicKeyProto())
                val encryptedServerHelloBuilder = EncryptedServerHello.newBuilder()

                buildServerHello(
                    serverHelloSignedBuilder,
                    encryptedServerHelloBuilder,
                )

                val serverHelloSignedBytes = serverHelloSignedBuilder.build().toByteString()

                this.staticKey?.let {
                    encryptedServerHelloBuilder.signature = ByteString.copyFrom(it.sign(serverHelloSignedBytes.toByteArray()))
                }

                val unencryptedServerHelloBuilder = UnencryptedServerHello.newBuilder()
                    .setSigned(serverHelloSignedBytes)
                    .setCryptoAlgorithm(CryptoAlgorithm.CryptoAlgorithmAes)

                val encryptKey = generateServerHelloKey()
                val ciphertext = CryptoUtils.encrypt(unencryptedServerHelloBuilder.cryptoAlgorithm, encryptKey, encryptedServerHelloBuilder.build().toByteArray())

                val sendPayload = Payload.newBuilder()
                    .setUnencryptedServerHello(unencryptedServerHelloBuilder.build().toByteString())
                    .setEncryptedMessage(ciphertext)
                    .build()

                writer.write(sendPayload)
                    .exceptionally {
                        handshakePromise.completeExceptionally(it)
                        null
                    }
            }
            payload.hasUnencryptedServerHello() -> {
                throw IllegalProtocolException()
            }
        }
        if (payload.hasEncryptedMessage()) {

        }
    }


}