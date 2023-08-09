package com.amazon.corretto.crypto.examples

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider
import com.amazon.corretto.crypto.provider.HkdfSpec
import com.amazonaws.encryptionsdk.internal.HmacKeyDerivationFunction
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import kotlin.test.Test
import kotlin.test.assertContentEquals

interface HkdfApi {
    fun hkdf(digest: String, ikm: ByteArray, salt: ByteArray, info: ByteArray, keyLen: Int): ByteArray
}

class AccpHkdfImpl : HkdfApi {
    override fun hkdf(digest: String, ikm: ByteArray, salt: ByteArray, info: ByteArray, keyLen: Int): ByteArray {
        val skf = SecretKeyFactory.getInstance("HkdfWith${digest}", AmazonCorrettoCryptoProvider.INSTANCE)
        val spec = HkdfSpec.hkdfSpec(ikm, salt, info, keyLen, null)
        return skf.generateSecret(spec).encoded
    }
}

class ESdkHkdfImpl : HkdfApi {
    override fun hkdf(digest: String, ikm: ByteArray, salt: ByteArray, info: ByteArray, keyLen: Int): ByteArray {
        val hkdf = HmacKeyDerivationFunction.getInstance(digest)
        hkdf.init(ikm, salt)
        return hkdf.deriveKey(info, keyLen)
    }

}

class Hkdf {
    @Test
    fun hkdfTest() {
        val srand = SecureRandom()
        val ikm = srand.randomSeq(10)
        val salt = srand.randomSeq(20)
        val info = srand.randomSeq(30)
        val keyLen = 100
        val accpHkdfImpl = AccpHkdfImpl()
        val eSdkHkdfImpl = ESdkHkdfImpl()
        val keyAccp = accpHkdfImpl.hkdf("HmacSHA256", ikm, salt, info, keyLen)
        val keyEsdk = eSdkHkdfImpl.hkdf("HmacSHA256", ikm, salt, info, keyLen)
        println("Key generated by HKDF implementation in Accp:\n${keyAccp.toHex()}")
        println("Key generated by HKDF implementation in eSDK:\n${keyEsdk.toHex()}")
        assertContentEquals(keyEsdk, keyAccp)
    }
}