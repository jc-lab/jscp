package kr.jclab.jscp

import com.google.protobuf.ByteString
import kr.jclab.jscp.crypto.CryptoUtils
import kr.jclab.jscp.crypto.OpKeyPair
import kr.jclab.jscp.payload.*
import java.lang.RuntimeException

open class ClientSecureChannel(
    writer: Writer,
    private val ephemeralKeyType: KeyType = KeyType.KeyTypeDHX25519,
    staticKey: OpKeyPair? = null,
) : SecureChannel(
    writer,
    staticKey,
) {
    private var unencryptedServerHello: UnencryptedServerHello? = null

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
            .setEphemeralKey(localEphemeralKey.toPublicKeyProto())

        val builder = ClientHello.newBuilder()
            .setVersion(1)

        buildClientHello(signedBuilder, builder)

        builder.signed = signedBuilder.build().toByteString()

        this.staticKey?.let {
            builder
                .setStaticKey(it.toPublicKeyProto())
                .setSignature(ByteString.copyFrom(it.sign(builder.signed.toByteArray())))
        }

        val clientHelloBytes = builder.build().toByteString()
        this.clientHelloHash = CryptoUtils.hashSha256(clientHelloBytes.toByteArray())

        val sendPayload = Payload.newBuilder()
            .setClientHello(clientHelloBytes)
            .build()
        writer.write(sendPayload)
    }

    override fun onMessage(payload: Payload) {
        when {
            payload.hasClientHello() -> {
                throw IllegalProtocolException()
            }
            payload.hasUnencryptedServerHello() -> {
                if (this.unencryptedServerHello != null) {
                    throw IllegalProtocolException()
                }
                val unencryptedServerHello = UnencryptedServerHello.parseFrom(payload.unencryptedServerHello)
                this.unencryptedServerHello = unencryptedServerHello

                val serverHelloSigned = ServerHelloSigned.parseFrom(unencryptedServerHello.signed)

                val remoteEphemeralKey = CryptoUtils.unmarshal(serverHelloSigned.ephemeralKey)
                this.remoteEphemeralKey = remoteEphemeralKey

                val ephemeralMasterKey = localEphemeralKey!!.privateKey.dhAgreement(remoteEphemeralKey)
                this.ephemeralMasterKey = ephemeralMasterKey

                val encryptKey = generateServerHelloKey()
                val plaintext = CryptoUtils.decrypt(unencryptedServerHello.cryptoAlgorithm, encryptKey, payload.encryptedMessage)

                val encryptedServerHello = EncryptedServerHello.parseFrom(plaintext)
                onServerHello(unencryptedServerHello, serverHelloSigned, encryptedServerHello)

                handshakePromise.complete(null)
            }
        }
    }
}