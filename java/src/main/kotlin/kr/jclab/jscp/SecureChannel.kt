package kr.jclab.jscp

import kr.jclab.jscp.crypto.CryptoUtils
import kr.jclab.jscp.crypto.OpKeyPair
import kr.jclab.jscp.crypto.OpPublicKey
import kr.jclab.jscp.payload.*
import java.io.ByteArrayOutputStream
import java.util.concurrent.CompletableFuture
import java.util.zip.Deflater
import java.util.zip.Inflater

abstract class SecureChannel(
    protected val writer: Writer,
    protected val serverMode: Boolean,
) : Receiver {
    enum class HandshakeState {
        NOT_STARTED,
        HELLO,
        SUCCESS,
        FAILED,
    }

    protected var handshakeState = HandshakeState.NOT_STARTED

    protected var localEphemeralKey: OpKeyPair? = null
    protected var remoteEphemeralKey: OpPublicKey? = null
    protected var ephemeralMasterKey: ByteArray? = null
    protected var clientHelloHash: ByteArray? = null

    protected val handshakePromise = CompletableFuture<Void?>()

    private var serverHelloKey: ByteArray? = null
    private var sessionKey: ByteArray? = null

    private var localEncryptKey: ByteArray? = null
    protected var localLastSeqNum: Long = 0
    private var remoteEncryptKey: ByteArray? = null
    protected var remoteLastSeqNum: Long = 0

    protected var cryptoAlgorithm: CryptoAlgorithm = CryptoAlgorithm.CryptoAlgorithmAes

    fun handshake(): CompletableFuture<Void?> {
        startHandshake()
        return handshakePromise
    }

    override fun onMessage(payload: Payload): ReceiveResult {
        when {
            payload.hasEncryptedMessage() -> {
                if (handshakeState != HandshakeState.SUCCESS) {
                    throw IllegalProtocolException()
                }
                
                val plaintext = decrypt(payload.encryptedMessage)
                return ReceiveResult(
                    data = plaintext,
                )
            }
        }

        return ReceiveResult()
    }

    fun send(data: ByteArray): CompletableFuture<Void?> {
        val encryptedMessage = this.encrypt(data)
        return this.writer.write(
            Payload.newBuilder()
                .setEncryptedMessage(encryptedMessage)
                .build()
        )
    }

    protected abstract fun startHandshake()

    protected fun setServerHelloKey(): ByteArray {
        val serverHelloKey = CryptoUtils.hkdfSha256(ephemeralMasterKey!!, clientHelloHash!!, "SERVER_HELLO".toByteArray(), 32)
        this.serverHelloKey = serverHelloKey
        return serverHelloKey
    }

    protected fun setSessionKey(unencryptedServerHelloHash: ByteArray, encryptedServerHelloHash: ByteArray) {
        val sessionKey = CryptoUtils.hkdfSha256(serverHelloKey!!, unencryptedServerHelloHash + encryptedServerHelloHash, "SESSION".toByteArray(), 32)
        this.sessionKey = sessionKey

        val serverEncryptKey = CryptoUtils.hkdfSha256(sessionKey, null, "SERVER".toByteArray(), 32)
        val clientEncryptKey = CryptoUtils.hkdfSha256(sessionKey, null, "CLIENT".toByteArray(), 32)

        if (serverMode) {
            this.localEncryptKey = serverEncryptKey
            this.remoteEncryptKey = clientEncryptKey
        } else {
            this.localEncryptKey = clientEncryptKey
            this.remoteEncryptKey = serverEncryptKey
        }
    }

    protected fun encrypt(plaintext: ByteArray, specificKey: ByteArray? = null): EncryptedMessage {
        val key = specificKey ?: localEncryptKey!!
        val compressionInfo = CompressionInfo.newBuilder()
            .setType(if (plaintext.size > 64) { CompressionType.CompressionZlib } else { CompressionType.CompressionNone })
            .build()
        val builder = EncryptedMessage.newBuilder()
            .setCompressionInfo(compressionInfo.toByteString())

        val compressed = compress(compressionInfo, plaintext)

        val seqNum = ++localLastSeqNum
        val authData = makeAuthData(seqNum, builder)
        return CryptoUtils.encrypt(
            cryptoAlgorithm,
            builder,
            key,
            authData,
            compressed
        )
    }

    protected fun decrypt(encryptedMessage: EncryptedMessage, specificKey: ByteArray? = null): ByteArray {
        val key = specificKey ?: remoteEncryptKey!!

        val seqNum = remoteLastSeqNum + 1
        val authData = makeAuthData(seqNum, encryptedMessage)

        val plaintext = CryptoUtils.decrypt(
            cryptoAlgorithm,
            key,
            authData,
            encryptedMessage
        )
        remoteLastSeqNum = seqNum // if no error
        return decompress(CompressionInfo.parseFrom(encryptedMessage.compressionInfo), plaintext)
    }

    private fun makeAuthData(sequenceNumber: Long, encryptedMessage: EncryptedMessageOrBuilder): ByteArray {
        return CryptoUtils.encodeLongBE(sequenceNumber) + encryptedMessage.compressionInfo.toByteArray()
    }

    private fun compress(info: CompressionInfo, input: ByteArray): ByteArray {
        if (info.type != CompressionType.CompressionZlib) {
            return input
        }

        val deflater = Deflater()

        deflater.setInput(input)
        deflater.finish()

        val buffer = ByteArray(1024)
        val output = ByteArrayOutputStream()
        while (true) {
            val written = deflater.deflate(buffer)
            if (written <= 0) break
            output.write(buffer, 0, written)
        }

        return output.toByteArray()
    }

    private fun decompress(info: CompressionInfo, input: ByteArray): ByteArray {
        if (info.type != CompressionType.CompressionZlib) {
            return input
        }

        val inflater = Inflater()
        inflater.setInput(input)

        val buffer = ByteArray(1024)
        val output = ByteArrayOutputStream()
        while (true) {
            val written = inflater.inflate(buffer)
            if (written > 0) {
                output.write(buffer, 0, written)
            }
            if (inflater.finished() || inflater.needsDictionary()) {
                break
            } else if (inflater.needsInput()) {
                throw RuntimeException("decompress failed")
            }
        }

        return output.toByteArray()
    }
}
