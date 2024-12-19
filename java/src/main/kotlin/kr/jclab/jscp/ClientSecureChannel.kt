package kr.jclab.jscp

import com.google.protobuf.ByteString
import kr.jclab.jscp.crypto.CryptoUtils
import kr.jclab.jscp.crypto.OpKeyPair
import kr.jclab.jscp.payload.*
import java.lang.RuntimeException

open class ClientSecureChannel(
    writer: Writer,
    private val ephemeralKeyType: KeyType = KeyType.KeyTypeDHX25519,
    private val staticKey: OpKeyPair? = null,
) : SecureChannel(
    writer = writer,
    serverMode = false,
) {
    init {
        if (ephemeralKeyType.number <= KeyType.KeyTypeDHStart.number || ephemeralKeyType.number >= KeyType.KeyTypeDHEnd.number) {
            throw RuntimeException("illegal ephemeralKeyType: ${ephemeralKeyType}")
        }
    }

    open fun buildClientHello(
        signedBuilder: ClientHelloSigned.Builder,
        clientHelloBuilder: ClientHello.Builder,
    ) {}

    /**
     * verify encryptedServerHello.signed & encryptedServerHello.signature
     */
    open fun onServerHello(
        unencryptedServerHello: UnencryptedServerHello,
        serverHelloSigned: ServerHelloSigned,
        encryptedServerHello: EncryptedServerHello,
    ) {}

    override fun startHandshake() {
        val localEphemeralKey = CryptoUtils.generateKeyPair(ephemeralKeyType)
        this.localEphemeralKey = localEphemeralKey

        val signedBuilder = ClientHelloSigned.newBuilder()
            .setEphemeralKey(localEphemeralKey.publicKey.toPublicKeyProto())

        val builder = ClientHello.newBuilder()
            .setVersion(1)

        buildClientHello(signedBuilder, builder)

        builder.signed = signedBuilder.build().toByteString()

        this.staticKey?.let {
            builder
                .setStaticKey(it.publicKey.toPublicKeyProto())
                .setSignature(ByteString.copyFrom(it.privateKey.sign(builder.signed.toByteArray())))
        }

        val clientHelloBytes = builder.build().toByteString()
        this.clientHelloHash = CryptoUtils.hashSha256(clientHelloBytes.toByteArray())

        val sendPayload = Payload.newBuilder()
            .setClientHello(clientHelloBytes)
            .build()
        this.handshakeState = HandshakeState.HELLO
        writer.write(sendPayload)
    }

    override fun onMessage(payload: Payload): ReceiveResult {
        return when {
            payload.hasClientHello() -> {
                throw IllegalProtocolException()
            }
            payload.hasUnencryptedServerHello() -> {
                if (handshakeState != HandshakeState.HELLO) {
                    throw IllegalProtocolException()
                }

                val unencryptedServerHello = UnencryptedServerHello.parseFrom(payload.unencryptedServerHello)
                val unencryptedServerHelloHash = CryptoUtils.hashSha256(payload.unencryptedServerHello.toByteArray())

                val serverHelloSigned = ServerHelloSigned.parseFrom(unencryptedServerHello.signed)

                val remoteEphemeralKey = CryptoUtils.unmarshal(serverHelloSigned.ephemeralKey)
                this.remoteEphemeralKey = remoteEphemeralKey

                val ephemeralMasterKey = localEphemeralKey!!.privateKey.dhAgreement(remoteEphemeralKey)
                this.ephemeralMasterKey = ephemeralMasterKey

                val encryptKey = setServerHelloKey()
                val encryptedServerHelloBytes = decrypt(payload.encryptedMessage, encryptKey)
                val encryptedServerHelloHash = CryptoUtils.hashSha256(encryptedServerHelloBytes)

                val encryptedServerHello = EncryptedServerHello.parseFrom(encryptedServerHelloBytes)
                onServerHello(unencryptedServerHello, serverHelloSigned, encryptedServerHello)

                setSessionKey(unencryptedServerHelloHash, encryptedServerHelloHash)

                handshakeState = HandshakeState.SUCCESS
                handshakePromise.complete(null)

                ReceiveResult()
            }
            else -> super.onMessage(payload)
        }
    }
}