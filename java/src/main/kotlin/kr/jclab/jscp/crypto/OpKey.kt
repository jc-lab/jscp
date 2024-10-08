package kr.jclab.jscp.crypto

import kr.jclab.jscp.payload.KeyType

interface OpKey {
    fun keyType(): KeyType
}