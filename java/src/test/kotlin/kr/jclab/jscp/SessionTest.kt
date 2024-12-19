package kr.jclab.jscp

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.future.await
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kr.jclab.jscp.crypto.*
import kr.jclab.jscp.payload.JcspPayload
import kr.jclab.jscp.state.SymmetricState
import org.assertj.core.api.Assertions.assertThat
import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.security.SecureRandom

class SessionTest {
    data class TestCase(
        val name: String,
        val serverAdditional: ByteArray?,
        val clientAdditional: ByteArray?,
        val expectAdditional: Boolean,
        val serverUseSignature: Boolean,
        val clientUseSignature: Boolean,
        val serverUseDHSignature: String?,
        val clientUseDHSignature: String?
    )

    private val testCases = listOf(
        TestCase(
            name = "no_static-no_static-wo_additional",
            serverAdditional = null,
            clientAdditional = null,
            expectAdditional = false,
            serverUseSignature = false,
            clientUseSignature = false,
            serverUseDHSignature = null,
            clientUseDHSignature = null
        ),
        TestCase(
            name = "no_static-no_static-with_additional",
            serverAdditional = "i am server".toByteArray(),
            clientAdditional = "i am client".toByteArray(),
            expectAdditional = true,
            serverUseSignature = false,
            clientUseSignature = false,
            serverUseDHSignature = null,
            clientUseDHSignature = null
        ),
        TestCase(
            name = "static(signature)-static(signature)-wo_additional",
            serverAdditional = null,
            clientAdditional = null,
            expectAdditional = false,
            serverUseSignature = true,
            clientUseSignature = true,
            serverUseDHSignature = null,
            clientUseDHSignature = null
        ),
        TestCase(
            name = "static(signature)-static(signature)-with_additional",
            serverAdditional = "i am server".toByteArray(),
            clientAdditional = "i am client".toByteArray(),
            expectAdditional = true,
            serverUseSignature = true,
            clientUseSignature = true,
            serverUseDHSignature = null,
            clientUseDHSignature = null
        ),
        TestCase(
            name = "static(x25519)-static(x25519)-wo_additional",
            serverAdditional = null,
            clientAdditional = null,
            expectAdditional = false,
            serverUseSignature = true,
            clientUseSignature = true,
            serverUseDHSignature = "x25519",
            clientUseDHSignature = "x25519"
        ),
        TestCase(
            name = "static(x25519)-static(x25519)-with_additional",
            serverAdditional = "i am server".toByteArray(),
            clientAdditional = "i am client".toByteArray(),
            expectAdditional = true,
            serverUseSignature = true,
            clientUseSignature = true,
            serverUseDHSignature = "x25519",
            clientUseDHSignature = "x25519"
        ),
        TestCase(
            name = "static(p256)-static(p256)-wo_additional",
            serverAdditional = null,
            clientAdditional = null,
            expectAdditional = false,
            serverUseSignature = true,
            clientUseSignature = true,
            serverUseDHSignature = "p256",
            clientUseDHSignature = "p256"
        ),
        TestCase(
            name = "static(p256)-static(p256)-with_additional",
            serverAdditional = "i am server".toByteArray(),
            clientAdditional = "i am client".toByteArray(),
            expectAdditional = true,
            serverUseSignature = true,
            clientUseSignature = true,
            serverUseDHSignature = "p256",
            clientUseDHSignature = "p256"
        ),
        TestCase(
            name = "no_static(p256)-static(p256)-with_additional",
            serverAdditional = "i am server".toByteArray(),
            clientAdditional = "i am client".toByteArray(),
            expectAdditional = true,
            serverUseSignature = false,
            clientUseSignature = true,
            serverUseDHSignature = "",
            clientUseDHSignature = "p256"
        ),
        TestCase(
            name = "static(p256)-no_static(p256)-with_additional",
            serverAdditional = "i am server".toByteArray(),
            clientAdditional = "i am client".toByteArray(),
            expectAdditional = true,
            serverUseSignature = true,
            clientUseSignature = false,
            serverUseDHSignature = "p256",
            clientUseDHSignature = ""
        ),
        TestCase(
            name = "data communication",
            serverAdditional = "i am server".toByteArray(),
            clientAdditional = "i am client".toByteArray(),
            expectAdditional = true,
            serverUseSignature = true,
            clientUseSignature = true,
            serverUseDHSignature = "p256",
            clientUseDHSignature = "p256"
        )
    )

    @TestFactory
    fun testCommunicationDynamic() = testCases.map { tc ->
        DynamicTest.dynamicTest(tc.name) {
            runTest {
                val secureRandom = SecureRandom()
                val buffer = ByteArray(65536)

                var serverPrivateKey: JscpPrivateKey? = null
                var clientPrivateKey: JscpPrivateKey? = null

                // 서버 키 설정
                if (tc.serverUseSignature) {
                    serverPrivateKey = when (tc.serverUseDHSignature) {
                        "x25519" -> X25519Algorithm.generate().private
                        "p256" -> ECCAlgorithm(KeyUsage.DH).generateKeyPair("P-256").first
                        else -> Ed25519Algorithm.generate().first
                    }
                }

                // 클라이언트 키 설정
                if (tc.clientUseSignature) {
                    clientPrivateKey = when (tc.clientUseDHSignature) {
                        "x25519" -> X25519Algorithm.generate().private
                        "p256" -> ECCAlgorithm(KeyUsage.DH).generateKeyPair("P-256").first
                        else -> Ed25519Algorithm.generate().first
                    }
                }

                // 통신 채널 설정
                val clientToServer = Channel<JcspPayload.Payload>(Channel.UNLIMITED)
                val serverToClient = Channel<JcspPayload.Payload>(Channel.UNLIMITED)
                val clientReceive = Channel<ByteArray>(Channel.UNLIMITED)
                val serverReceive = Channel<ByteArray>(Channel.UNLIMITED)

                // 세션 생성
                val server = Session(
                    initiator = false,
                    staticKeyPair = serverPrivateKey
                ) { payload -> runBlocking { serverToClient.send(payload) } }
                server.onReceive = { data ->
                    runBlocking { serverReceive.send(data) }
                }

                val client = Session(
                    initiator = true,
                    staticKeyPair = clientPrivateKey
                ) { payload -> runBlocking { clientToServer.send(payload) } }
                client.onReceive = { data ->
                    runBlocking { clientReceive.send(data) }
                }

                // 테스트용 SymmetricState 설정
                client.symmetricStateFactory = { TestSymmetricState("client") }
                server.symmetricStateFactory = { TestSymmetricState("server") }

                // 메시지 핸들링
                launch {
                    for (payload in serverToClient) {
                        client.handleReceive(payload)
                    }
                }

                launch {
                    for (payload in clientToServer) {
                        server.handleReceive(payload)
                    }
                }

                // 핸드쉐이크 수행
                val clientHandshakeResult = client.handshake(tc.clientAdditional)
                val serverHandshakeResult = server.handshake(tc.serverAdditional)

                // 결과 검증
                withTimeout(500) {
                    val clientResult = clientHandshakeResult.await()
                    val serverResult = serverHandshakeResult.await()

                    println(clientResult)
                    println(serverResult)

                    // Additional 데이터 검증
                    if (tc.expectAdditional) {
                        assertThat(clientResult.peerAdditionalData)
                            .isEqualTo(tc.serverAdditional)
                        assertThat(serverResult.peerAdditionalData)
                            .isEqualTo(tc.clientAdditional)
                    } else {
                        assertThat(clientResult.peerAdditionalData).isNull()
                        assertThat(serverResult.peerAdditionalData).isNull()
                    }

                    // 공개키 검증
                    if (tc.serverUseSignature) {
                        compareSignaturePublicKey(
                            serverPrivateKey,
                            clientResult.remotePublicKey
                        )
                    }
                    if (tc.clientUseSignature) {
                        compareSignaturePublicKey(
                            clientPrivateKey,
                            serverResult.remotePublicKey
                        )
                    }

                    // SymmetricState 검증
                    val clientStateA = client.localState as TestSymmetricState
                    val clientStateB = server.remoteState as TestSymmetricState
                    assertThat(clientStateA.recordedKeys).hasSize(clientStateB.recordedKeys.size)
                    for (i in 0 until clientStateA.recordedKeys.size) {
                        assertArrayEquals(clientStateA.recordedKeys[i], clientStateB.recordedKeys[i])
                    }

                    val serverStateA = client.remoteState as TestSymmetricState
                    val serverStateB = server.localState as TestSymmetricState
                    assertThat(serverStateA.recordedKeys).hasSize(serverStateB.recordedKeys.size)
                    for (i in 0 until clientStateA.recordedKeys.size) {
                        assertArrayEquals(serverStateA.recordedKeys[i], serverStateB.recordedKeys[i])
                    }

                    // 데이터 통신 테스트
                    repeat(100) {
                        secureRandom.nextBytes(buffer)

                        server.write(buffer)
                        val clientReceived = clientReceive.receive()
                        assertThat(clientReceived).isEqualTo(buffer)

                        secureRandom.nextBytes(buffer)
                        client.write(buffer)
                        val serverReceived = serverReceive.receive()
                        assertThat(serverReceived).isEqualTo(buffer)
                    }
                }

                // 정리
                clientToServer.close()
                serverToClient.close()
            }
        }
    }

    private fun compareSignaturePublicKey(expectedPrivateKey: JscpPrivateKey?, actual: JscpPublicKey?) {
        assertThat(actual?.marshalToProto()).isEqualTo(expectedPrivateKey?.getPublic()?.marshalToProto())
    }
}

class TestSymmetricState(
    val name: String,
) : SymmetricState() {
    val recordedKeys = mutableListOf<ByteArray>()

    override fun mixKey(cipher: CipherAlgorithm, key: ByteArray) {
//        println("[${name}] MIX KEY: ${Hex.toHexString(key)}")
        recordedKeys.add(key)
        super.mixKey(cipher, key)
    }

    override fun mixHash(data: ByteArray) {
//        println("[${name}] MIX HASH: ${Hex.toHexString(data)}")
        super.mixHash(data)
    }
}