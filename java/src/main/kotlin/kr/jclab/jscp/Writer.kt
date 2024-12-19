package kr.jclab.jscp

import kr.jclab.jscp.payload.Payload
import java.util.concurrent.CompletableFuture

interface Writer {
    fun write(payload: Payload): CompletableFuture<Void?>
}