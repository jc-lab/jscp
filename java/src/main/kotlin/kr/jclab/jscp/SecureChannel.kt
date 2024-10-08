package kr.jclab.jscp

import kr.jclab.jscp.crypto.CryptoUtils
import kr.jclab.jscp.crypto.OpKeyPair
import kr.jclab.jscp.crypto.OpPublicKey
import kr.jclab.jscp.payload.ClientHello
import kr.jclab.jscp.payload.Payload
import java.util.concurrent.CompletableFuture

abstract class SecureChannel(
    protected val writer: Writer,
    protected val staticKey: OpKeyPair? = null,
) : Receiver {
    protected var localEphemeralKey: OpKeyPair? = null
    protected var remoteEphemeralKey: OpPublicKey? = null
    protected var ephemeralMasterKey: ByteArray? = null
    protected var clientHelloHash: ByteArray? = null

    protected val handshakePromise = CompletableFuture<Void?>()

    fun handshake(): CompletableFuture<Void?> {
        startHandshake()
        return handshakePromise
    }

    protected abstract fun startHandshake()

    protected fun generateServerHelloKey(): ByteArray {
        return CryptoUtils.hkdfSha256(ephemeralMasterKey!!, clientHelloHash!!, "SERVER_HELLO".toByteArray(), 32)
    }
}