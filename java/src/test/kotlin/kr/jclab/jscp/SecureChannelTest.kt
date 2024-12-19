package kr.jclab.jscp

import jdk.jshell.SourceCodeAnalysis.Completeness
import kr.jclab.jscp.crypto.ProviderHolder
import kr.jclab.jscp.payload.Payload
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.concurrent.CompletableFuture
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class SecureChannelTest {
    @Test
    fun handshakeTest() {
        makePair()
    }

    @Test
    fun dataTestSmall() {
        val context = makePair()

        context.server.send("HELLO1".toByteArray())
        context.server.send("HELLO2".toByteArray())
        context.client.send("WORLD1".toByteArray())
        context.client.send("WORLD2".toByteArray())
        context.server.send("HELLO3".toByteArray())
        context.client.send("WORLD3".toByteArray())
        context.server.send("HELLO4".toByteArray())
        context.client.send("WORLD4".toByteArray())

        assertThat(context.clientReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("HELLO1".toByteArray())
        assertThat(context.clientReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("HELLO2".toByteArray())
        assertThat(context.clientReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("HELLO3".toByteArray())
        assertThat(context.clientReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("HELLO4".toByteArray())
        assertThat(context.serverReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("WORLD1".toByteArray())
        assertThat(context.serverReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("WORLD2".toByteArray())
        assertThat(context.serverReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("WORLD3".toByteArray())
        assertThat(context.serverReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo("WORLD4".toByteArray())
    }

    @Test
    fun dataTestRandomLarge() {
        val context = makePair()

        val r1 = CompletableFuture<Void?>()
        val t1 = Thread {
            try {
                val dataSize = ProviderHolder.SECURE_RANDOM.nextInt(32768)
                val buffer = "HELLO".repeat(100).toByteArray() + ByteArray(dataSize).also { ProviderHolder.SECURE_RANDOM.nextBytes(it) }
                context.server.send(buffer)
                assertThat(context.clientReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo(buffer)
                r1.complete(null)
            } catch (e: Exception) {
                r1.completeExceptionally(e)
            }
        }.also {
            it.start()
        }

        val r2 = CompletableFuture<Void?>()
        val t2 = Thread {
            try {
                val dataSize = ProviderHolder.SECURE_RANDOM.nextInt(32768)
                val buffer = "HELLO".repeat(100).toByteArray() + ByteArray(dataSize).also { ProviderHolder.SECURE_RANDOM.nextBytes(it) }
                context.client.send(buffer)
                assertThat(context.serverReceive.poll(1, TimeUnit.MILLISECONDS)).isEqualTo(buffer)
                r2.complete(null)
            } catch (e: Exception) {
                r2.completeExceptionally(e)
            }
        }.also {
            it.start()
        }

        r1.get()
        r2.get()
    }

    class TestContext(
        val server: ServerSecureChannel,
        val client: ClientSecureChannel,
        val serverReceive: LinkedBlockingQueue<ByteArray>,
        val clientReceive: LinkedBlockingQueue<ByteArray>,
    )

    fun makePair(): TestContext {
        val clientRef = AtomicReference<ClientSecureChannel>()

        val serverReceive = LinkedBlockingQueue<ByteArray>(4)
        val clientReceive = LinkedBlockingQueue<ByteArray>(4)

        val server = ServerSecureChannel(
            writer = object : Writer {
                override fun write(payload: Payload): CompletableFuture<Void?> {
                    clientRef.get().onMessage(payload)
                        .data?.let { clientReceive.add(it) }

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
                        .data?.let { serverReceive.add(it) }

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

        return TestContext(server, client, serverReceive, clientReceive)
    }
}