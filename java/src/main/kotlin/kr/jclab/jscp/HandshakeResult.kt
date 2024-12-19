package kr.jclab.jscp

import kr.jclab.jscp.crypto.JscpPublicKey

data class HandshakeResult(
    val remotePublicKey: JscpPublicKey? = null,
    val peerAdditionalData: ByteArray? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HandshakeResult

        if (remotePublicKey != other.remotePublicKey) return false
        if (peerAdditionalData != null) {
            if (other.peerAdditionalData == null) return false
            if (!peerAdditionalData.contentEquals(other.peerAdditionalData)) return false
        } else if (other.peerAdditionalData != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = remotePublicKey?.hashCode() ?: 0
        result = 31 * result + (peerAdditionalData?.contentHashCode() ?: 0)
        return result
    }
}
