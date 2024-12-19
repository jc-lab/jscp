package kr.jclab.jscp.state

import java.nio.ByteBuffer
import java.nio.ByteOrder

class Nonce(size: Int) {
    private var n: Long = 0
    private val bytesBuffer = ByteArray(size)
    private val buffer = ByteBuffer.wrap(bytesBuffer)

    init {
        buffer.order(ByteOrder.LITTLE_ENDIAN)
        buffer.putLong(size - 8, n)
    }

    fun increment() {
        n++
        buffer.putLong(bytesBuffer.size - 8, n)
    }

    val bytes get(): ByteArray = bytesBuffer.clone()

    fun getUint64(): Long = n
}