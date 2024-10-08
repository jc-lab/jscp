package kr.jclab.jscp

import kr.jclab.jscp.payload.Payload
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicReference

class SecureChannelTest {
    @Test
    fun bidirectionTest() {
        val clientRef = AtomicReference<ClientSecureChannel>()

        val server = ServerSecureChannel(
            writer = object : Writer {
                override fun write(payload: Payload): CompletableFuture<Void?> {
                    clientRef.get().onMessage(payload)
                    return CompletableFuture<Void?>().also {
                        it.complete(null)
                    }
                }

            }
        )
        val client = ClientSecureChannel(
            writer = object : Writer {
                override fun write(payload: Payload): CompletableFuture<Void?> {
                    server.onMessage(payload)
                    return CompletableFuture<Void?>().also {
                        it.complete(null)
                    }
                }
            }
        )
        clientRef.set(client)

        server.handshake()
            .whenComplete { _, ex ->
                if (ex == null) {
                    System.out.println("SERVER: Handshake OK")
                } else {
                    System.out.println("SERVER: Handshake FAILED")
                    ex.printStackTrace()
                }
            }

        client.handshake().get()
    }
}