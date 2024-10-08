/**
 * Copyright 2021 JC-Lab (joseph@jc-lab.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kr.jclab.gradlehelper

import java.lang.ProcessBuilder
import java.util.concurrent.CompletableFuture
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.lang.RuntimeException

object ProcessHelper {
    fun executeCommand(command: List<String>): String {
        val process = ProcessBuilder(command)
            .redirectError(ProcessBuilder.Redirect.INHERIT)
            .start()
        val promise = CompletableFuture<String>()
        val thread = Thread {
            try {
                promise.complete(process.inputStream.bufferedReader().readText().trim())
            } catch (e: IOException) {
                promise.completeExceptionally(e)
            }
        }
        thread.start()
        process.waitFor(10, TimeUnit.SECONDS)
        if (process.exitValue() != 0) {
            throw RuntimeException("exitCode=\${process.exitValue()}")
        }
        return promise.get()
    }
}
