package kr.jclab.jscp

import kr.jclab.jscp.payload.Payload

interface Receiver {
    fun onMessage(payload: Payload): ReceiveResult
}