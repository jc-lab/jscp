package kr.jclab.jscp

import com.google.protobuf.ByteString
import kr.jclab.jscp.crypto.CryptoUtils
import kr.jclab.jscp.crypto.OpKeyPair
import kr.jclab.jscp.payload.*

open class ServerSecureChannel(
    writer: Writer,
    private val staticKey: OpKeyPair? = null,
) : SecureChannel(
    writer = writer,
    serverMode = true,
) {
    private var clientHello: ClientHello? = null
    private var signedClientHello: ClientHelloSigned? = null

    open fun onClientHello(clientHello: ClientHello) {}
    open fun buildServerHello(
        serverHelloSignedBuilder: ServerHelloSigned.Builder,
        encryptedServerHelloBuilder: EncryptedServerHello.Builder,
    ) {}

    init {
        handshakeState = HandshakeState.HELLO
    }

    override fun startHandshake() {}

    override fun onMessage(payload: Payload): ReceiveResult {
        return when {
            payload.hasClientHello() -> {
                if (handshakeState != HandshakeState.HELLO) {
                    throw IllegalProtocolException()
                }

                val clientHello = ClientHello.parseFrom(payload.clientHello)
                val clientHelloHash = CryptoUtils.hashSha256(payload.clientHello.toByteArray())
                this.clientHello = clientHello
                this.clientHelloHash = clientHelloHash

                if (!clientHello.signature.isEmpty) {
                    val clientStaticKey = CryptoUtils.unmarshal(clientHello.staticKey)
                    clientStaticKey.verify(clientHello.signed.toByteArray(), clientHello.signature.toByteArray())
                }

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
                    .setEphemeralKey(localEphemeralKey.publicKey.toPublicKeyProto())
                val encryptedServerHelloBuilder = EncryptedServerHello.newBuilder()

                buildServerHello(
                    serverHelloSignedBuilder,
                    encryptedServerHelloBuilder,
                )

                val serverHelloSignedBytes = serverHelloSignedBuilder.build().toByteString()

                this.staticKey?.let {
                    encryptedServerHelloBuilder.signature = ByteString.copyFrom(it.privateKey.sign(serverHelloSignedBytes.toByteArray()))
                }

                val encryptedServerHelloBytes = encryptedServerHelloBuilder.build().toByteArray()
                val encryptedServerHelloHash = CryptoUtils.hashSha256(encryptedServerHelloBytes)

                val unencryptedServerHello = UnencryptedServerHello.newBuilder()
                    .setSigned(serverHelloSignedBytes)
                    .setCryptoAlgorithm(CryptoAlgorithm.CryptoAlgorithmAes)
                    .build()
                val unencryptedServerHelloBytes = unencryptedServerHello.toByteArray()
                val unencryptedServerHelloHash = CryptoUtils.hashSha256(unencryptedServerHelloBytes)

                val encryptKey = setServerHelloKey()
                val ciphertext = encrypt(encryptedServerHelloBytes, encryptKey)

                val sendPayload = Payload.newBuilder()
                    .setUnencryptedServerHello(ByteString.copyFrom(unencryptedServerHelloBytes))
                    .setEncryptedMessage(ciphertext)
                    .build()

                setSessionKey(unencryptedServerHelloHash, encryptedServerHelloHash)

                handshakeState = HandshakeState.SUCCESS
                writer.write(sendPayload)
                    .thenAccept {
                        handshakePromise.complete(null)
                    }
                    .exceptionally {
                        handshakePromise.completeExceptionally(it)
                        null
                    }

                ReceiveResult()
            }
            payload.hasUnencryptedServerHello() -> {
                throw IllegalProtocolException()
            }
            else -> super.onMessage(payload)
        }
    }
}