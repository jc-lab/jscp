package kr.jclab.jscp.state

import kr.jclab.jscp.crypto.CipherAlgorithm

class CipherState(
    val cipher: CipherAlgorithm,
    val key: ByteArray
) {
    val nonce = Nonce(12)
}