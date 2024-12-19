package kr.jclab.jscp.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider

object SecurityHolder {
    val PROVIDER = BouncyCastleProvider()
}
