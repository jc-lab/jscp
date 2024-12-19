package kr.jclab.jscp.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom

object ProviderHolder {
    val BOUNCY_CASTLE = BouncyCastleProvider()
    val SECURE_RANDOM = SecureRandom()
}
