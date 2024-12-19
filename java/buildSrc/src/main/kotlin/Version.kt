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

import kr.jclab.gradlehelper.ProcessHelper

object Version {
    val KOTLIN = "1.9.25"
    val NETTY = "4.1.114.Final"
    val SPRING_FW = "6.1.13"
    val PROTOBUF = "4.28.2"
    val BOUNCY_CASLTE = "1.78.1"

    val PROJECT by lazy { getVersionFromGit() }

    fun getVersionFromGit(): String {
        return runCatching {
            val version = (
                System.getenv("CI_COMMIT_TAG")
                    ?.takeIf { it.isNotEmpty() }
                    ?: ProcessHelper.executeCommand(listOf("git", "describe", "--tags"))
                        .split("\n")[0]
                )
                .trim()
            if (version.startsWith("v")) {
                version.substring(1)
            } else version
        }.getOrElse {
            runCatching {
                ProcessHelper.executeCommand(listOf("git", "rev-parse", "HEAD"))
                    .split("\n")[0].trim() + "-SNAPSHOT"
            }.getOrElse {
                "unknown"
            }
        }
    }
}