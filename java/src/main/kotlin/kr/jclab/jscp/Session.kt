package kr.jclab.jscp

import com.google.protobuf.ByteString
import kr.jclab.jscp.crypto.*
import kr.jclab.jscp.payload.JcspPayload
import kr.jclab.jscp.state.SymmetricState
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CompletableFuture

class Session(
    private val initiator: Boolean,
    private val staticKeyPair: JscpPrivateKey? = null,
    private val send: (JcspPayload.Payload) -> Unit
) {
    var onReceive: ((ByteArray) -> Unit)? = null

    internal var symmetricStateFactory: (() -> SymmetricState)? = null

    internal lateinit var localState: SymmetricState
    internal lateinit var remoteState: SymmetricState

    private var dhAlgorithm: DHAlgorithm? = null
    private var ephemeralKeyPair: DHKeyPair? = null
    private var remoteEphemeralPublicKey: DHPublicKey? = null
    private var remotePublicKey: JscpPublicKey? = null

    private var handshakeResult = HandshakeResult()
    private var handshakePromise: ((Result<HandshakeResult>) -> Unit)? = null
    private var handshakeAdditionalData: ByteArray? = null

    private val availableEphemeralKeyAlgorithms = mutableListOf(
        JcspPayload.DHAlgorithm.DHX25519,
        JcspPayload.DHAlgorithm.DHECC
    )

    private val availableCipherAlgorithms = mutableListOf(
        JcspPayload.CipherAlgorithm.CipherAesGcm
    )

    init {
        if (staticKeyPair?.isDHKey() == true) {
            val dhKey = staticKeyPair as DHPrivateKey
            availableEphemeralKeyAlgorithms.clear()
            availableEphemeralKeyAlgorithms.add(dhKey.getDHAlgorithmProto())
        }
    }

    fun handshake(additional: ByteArray? = null): CompletableFuture<HandshakeResult> {
        val future = CompletableFuture<HandshakeResult>()

        localState = symmetricStateFactory?.invoke() ?: SymmetricState()
        remoteState = symmetricStateFactory?.invoke() ?: SymmetricState()

        handshakeAdditionalData = additional
        handshakePromise = { result ->
            result.fold(
                onSuccess = { future.complete(it) },
                onFailure = { future.completeExceptionally(it) }
            )
        }

        if (initiator) {
            try {
                sendHello(false)
            } catch (e: Exception) {
                future.completeExceptionally(e)
            }
        }

        return future
    }

    fun handleReceive(payload: JcspPayload.Payload) {
        try {
            when (payload.payloadType) {
                JcspPayload.PayloadType.PayloadHello ->
                    handleHello(payload.data.toByteArray(), false)
                JcspPayload.PayloadType.PayloadHelloWithChangeAlgorithm ->
                    handleHello(payload.data.toByteArray(), true)
                JcspPayload.PayloadType.PayloadEncryptedMessage ->
                    handleEncryptedMessage(payload.data.toByteArray())
                else -> throw IllegalArgumentException("Invalid payload type: ${payload.payloadType}")
            }
        } catch (e: Exception) {
            handshakePromise?.invoke(Result.failure(e))
        }
    }

    fun write(data: ByteArray) {
        try {
            val message = JcspPayload.EncryptedMessage.newBuilder()
                .setData(ByteString.copyFrom(data))
                .build()

            val plaintext = message.toByteArray()
            val ciphertext = localState.encryptWithAd(plaintext, ByteArray(0))

            val payload = JcspPayload.Payload.newBuilder()
                .setPayloadType(JcspPayload.PayloadType.PayloadEncryptedMessage)
                .setData(ByteString.copyFrom(ciphertext))
                .build()

            send(payload)
        } catch (e: Exception) {
            // Handle error
        }
    }

    private fun handleHello(payloadRaw: ByteArray, retry: Boolean) {
        var handshakeFinish = false
        var sendRetry = false

        val hello = JcspPayload.Hello.parseFrom(payloadRaw)
        val helloBytes = JcspPayload.HelloBytes.parseFrom(payloadRaw)
        val helloSignedBytes = JcspPayload.HelloSignedBytes.parseFrom(helloBytes.signed)

        var remotePublicKey: JscpPublicKey? = null
        if (hello.signed.hasPublicKey()) {
            val publicKeyAlgorithm = Registry.getPublicAlgorithm(
                hello.signed.publicKey.format,
                hello.signed.dhAlsoPublicKey
            )
            remotePublicKey = publicKeyAlgorithm.unmarshalPublicKey(
                hello.signed.publicKey.data.toByteArray()
            )

            if (!hello.signed.dhAlsoPublicKey) {
                val sigKey = remotePublicKey as SignaturePublicKey
                if (!sigKey.verify(helloBytes.signed.toByteArray(), helloBytes.signature.toByteArray())) {
                    throw IllegalStateException("Signature verification failed")
                }
            }
        }

        // Check cipher algorithm compatibility
        if (!availableCipherAlgorithms.contains(hello.signed.cipherAlgorithm)) {
            if (retry) {
                throw IllegalStateException("No cipher algorithm supported")
            }

            availableCipherAlgorithms.retainAll { hello.signed.supportCipherList.contains(it) }
            if (availableCipherAlgorithms.isEmpty()) {
                throw IllegalStateException("No cipher algorithm supported")
            }

            sendRetry = true
        }

        // Check DH algorithm compatibility
        if (!availableEphemeralKeyAlgorithms.contains(hello.signed.ephemeralKey.algorithm)) {
            if (retry) {
                throw IllegalStateException("No DH algorithm supported")
            }

            availableEphemeralKeyAlgorithms.retainAll { hello.signed.supportDhList.contains(it) }
            if (availableEphemeralKeyAlgorithms.isEmpty()) {
                throw IllegalStateException("No DH algorithm supported")
            }

            sendRetry = true
        }

        if (retry || sendRetry) {
            handshakeResult = HandshakeResult()
            localState = symmetricStateFactory?.invoke() ?: SymmetricState()
            remoteState = symmetricStateFactory?.invoke() ?: SymmetricState()
            ephemeralKeyPair = null

            if (sendRetry) {
                sendHello(true)
                return
            }
        }

        val cipherAlgorithm = Registry.getCipherAlgorithm(hello.signed.cipherAlgorithm)

        var dhAlgorithm: DHAlgorithm? = null

        remoteState.mixHash(encodeInt32(hello.version))

        if (remotePublicKey != null) {
            if (hello.signed.dhAlsoPublicKey) {
                dhAlgorithm = (remotePublicKey as DHPublicKey).getDHAlgorithm()
                ephemeralKeyPair?.let {
                    val sharedKey = it.private.dh(remotePublicKey)
                    remoteState.mixKey(cipherAlgorithm, sharedKey)
                    localState.mixKey(cipherAlgorithm, sharedKey)
                }
            } else {
                remoteState.mixHash(helloSignedBytes.publicKey.toByteArray())
            }
            this.remotePublicKey = remotePublicKey
            handshakeResult = handshakeResult.copy(
                remotePublicKey = remotePublicKey
            )
        }

        if (dhAlgorithm == null) {
            dhAlgorithm = getDHAlgorithm(hello.signed.ephemeralKey.algorithm)
        }
        this.dhAlgorithm = dhAlgorithm

        remoteEphemeralPublicKey = dhAlgorithm.unmarshalDHPublicKey(
            hello.signed.ephemeralKey.data.toByteArray()
        )

        if (ephemeralKeyPair == null && hello.signed.additional.size() > 0) {
            handshakeResult = handshakeResult.copy(
                peerAdditionalData = remoteState.mixHashAndDecrypt(hello.signed.additional.toByteArray())
            )
        }

        if (staticKeyPair?.isDHKey() == true) {
            val localDHKey = staticKeyPair as DHPrivateKey
            val sharedKey = localDHKey.dh(remoteEphemeralPublicKey!!)
            localState.mixKey(cipherAlgorithm, sharedKey)
            remoteState.mixKey(cipherAlgorithm, sharedKey)
        }

        if (ephemeralKeyPair != null) {
            val sharedKey = ephemeralKeyPair!!.private.dh(remoteEphemeralPublicKey!!)
            localState.mixKey(cipherAlgorithm, sharedKey)
            remoteState.mixKey(cipherAlgorithm, sharedKey)
            handshakeFinish = true
        } else {
            remoteState.mixHash(helloSignedBytes.ephemeralKey.toByteArray())
        }

        if (ephemeralKeyPair != null && hello.signed.additional.size() > 0) {
            handshakeResult = handshakeResult.copy(
                peerAdditionalData = remoteState.mixHashAndDecrypt(hello.signed.additional.toByteArray())
            )
        }

        if (helloBytes.signature.size() > 0) {
            remoteState.mixHash(helloBytes.signature.toByteArray())
        }

        if (handshakeFinish) {
            handshakePromise?.invoke(Result.success(handshakeResult))
        } else {
            sendHello(false)
        }
    }

    private fun handleEncryptedMessage(payloadRaw: ByteArray) {
        val plaintext = remoteState.decryptWithAd(payloadRaw, ByteArray(0))
        val message = JcspPayload.EncryptedMessage.parseFrom(plaintext)
        onReceive?.invoke(message.data.toByteArray())
    }

    private fun sendHello(changeAlgorithm: Boolean) {
        var handshakeFinish = false

        val dhAlgorithm = getDHAlgorithm(availableEphemeralKeyAlgorithms[0])
        val cipherAlgorithm = Registry.getCipherAlgorithm(availableCipherAlgorithms[0])

        val helloBuilder = JcspPayload.HelloBytes.newBuilder()
            .setVersion(1)

        localState.mixHash(encodeInt32(1))

        val helloSignedBuilder = JcspPayload.HelloSignedBytes.newBuilder()
            .addAllSupportDh(availableEphemeralKeyAlgorithms)
            .addAllSupportCipher(availableCipherAlgorithms)
            .setCipherAlgorithm(cipherAlgorithm.getType())

        if (staticKeyPair != null) {
            val publicKeyProto = staticKeyPair.getPublic().marshalToProto()
            val publicKeyBytes = publicKeyProto.toByteString()
            helloSignedBuilder.setPublicKey(publicKeyBytes)

            if (staticKeyPair.isSignatureKey()) {
                localState.mixHash(publicKeyBytes.toByteArray())
            } else if (staticKeyPair.isDHKey()) {
                helloSignedBuilder.setDhAlsoPublicKey(true)
            }
        }

        if (ephemeralKeyPair == null) {
            ephemeralKeyPair = dhAlgorithm.generate()

            if (remotePublicKey?.isDHKey() == true) {
                val remoteKey = remotePublicKey as DHPublicKey
                val shared = ephemeralKeyPair!!.private.dh(remoteKey)
                localState.mixKey(cipherAlgorithm, shared)
                remoteState.mixKey(cipherAlgorithm, shared)
            }
        }

        val ephemeralPublicKey = JcspPayload.DHPublicKey.newBuilder()
            .setAlgorithm(dhAlgorithm.getType())
            .setData(ByteString.copyFrom(ephemeralKeyPair!!.public.marshal()))
            .build()
        val ephemeralKeyBytes = ephemeralPublicKey.toByteString()
        helloSignedBuilder.setEphemeralKey(ephemeralKeyBytes)

        if (remoteEphemeralPublicKey != null) {
            val sharedKey = ephemeralKeyPair!!.private.dh(remoteEphemeralPublicKey!!)
            localState.mixKey(cipherAlgorithm, sharedKey)
            remoteState.mixKey(cipherAlgorithm, sharedKey)
            handshakeFinish = true
        } else {
            localState.mixHash(ephemeralKeyBytes.toByteArray())
        }

        if (handshakeAdditionalData != null && handshakeAdditionalData!!.isNotEmpty()) {
            val encrypted = localState.encryptAndMixHash(handshakeAdditionalData!!, false)
            helloSignedBuilder.setAdditional(ByteString.copyFrom(encrypted))
        }

        val signedBytes = helloSignedBuilder.build()
        val signedByteArray = signedBytes.toByteArray()
        helloBuilder.setSigned(ByteString.copyFrom(signedByteArray))

        if (staticKeyPair?.isSignatureKey() == true) {
            val signatureKey = staticKeyPair as SignaturePrivateKey
            val signature = signatureKey.sign(signedByteArray)
            helloBuilder.setSignature(ByteString.copyFrom(signature))
            localState.mixHash(signature)
        }

        if (handshakeFinish) {
            handshakePromise?.invoke(Result.success(handshakeResult))
        }

        val payloadType = if (changeAlgorithm) {
            JcspPayload.PayloadType.PayloadHelloWithChangeAlgorithm
        } else {
            JcspPayload.PayloadType.PayloadHello
        }

        val payload = JcspPayload.Payload.newBuilder()
            .setPayloadType(payloadType)
            .setData(helloBuilder.build().toByteString())
            .build()

        send(payload)
    }

    private fun getDHAlgorithm(candidate: JcspPayload.DHAlgorithm): DHAlgorithm {
        dhAlgorithm?.let { return it }

        if (staticKeyPair?.isDHKey() == true) {
            return (staticKeyPair as DHPrivateKey).getDHAlgorithm()
        }

        return Registry.getDHAlgorithm(candidate)
    }

    private fun encodeInt32(value: Int): ByteArray {
        return ByteBuffer.allocate(4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(value)
            .array()
    }
}
