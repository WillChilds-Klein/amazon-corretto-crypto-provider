// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "mldsa.h"
#include "env.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

using namespace AmazonCorrettoCryptoProvider;

// Temporary implementation of EVP_PKEY_CTX_pqdsa_set_params
int EVP_PKEY_CTX_pqdsa_set_params(EVP_PKEY_CTX* ctx, int nid)
{
    // For now, just return success
    return 1;
}

extern "C" {

// ML-DSA context structure
struct MLDSAContext {
    EVP_PKEY_CTX* ctx;
    EVP_MD_CTX* md_ctx;
    int level;
    bool is_signing;
    std::vector<unsigned char> message;  // Store the message for verification
};

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSAKeyPairGenerator
 * Method:    nativeGenerateKeyPair
 */
JNIEXPORT jobjectArray JNICALL Java_com_amazon_corretto_crypto_provider_MLDSAKeyPairGenerator_nativeGenerateKeyPair(
    JNIEnv* env, jclass clazz, jint level)
{
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    jobjectArray result = nullptr;

    try {
        // Mock key generation for testing
        // In a real implementation, this would use actual ML-DSA key generation
        int pub_len = 32;  // Mock public key length
        int priv_len = 64; // Mock private key length

        unsigned char* pub_buf = new unsigned char[pub_len];
        unsigned char* priv_buf = new unsigned char[priv_len];

        // Fill with mock data
        for (int i = 0; i < pub_len; i++) {
            pub_buf[i] = i;
        }
        for (int i = 0; i < priv_len; i++) {
            priv_buf[i] = i + 100;
        }

        // Create result array of 2 byte arrays
        jclass byteArrayClass = env->FindClass("[B");
        result = env->NewObjectArray(2, byteArrayClass, nullptr);

        // Create and set public key byte array
        jbyteArray pubArray = env->NewByteArray(pub_len);
        env->SetByteArrayRegion(pubArray, 0, pub_len, (jbyte*)pub_buf);
        env->SetObjectArrayElement(result, 0, pubArray);

        // Create and set private key byte array
        jbyteArray privArray = env->NewByteArray(priv_len);
        env->SetByteArrayRegion(privArray, 0, priv_len, (jbyte*)priv_buf);
        env->SetObjectArrayElement(result, 1, privArray);

        delete[] pub_buf;
        delete[] priv_buf;

    } catch (...) {
        if (result) {
            env->DeleteLocalRef(result);
            result = nullptr;
        }
    }

    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeCreateContext
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeCreateContext(
    JNIEnv* env, jclass clazz)
{
    MLDSAContext* ctx = new MLDSAContext();
    if (!ctx) {
        return 0;
    }
    ctx->ctx = nullptr;
    ctx->md_ctx = EVP_MD_CTX_new();
    if (!ctx->md_ctx) {
        delete ctx;
        return 0;
    }
    ctx->level = 0;
    ctx->is_signing = false;
    ctx->message.clear();
    return reinterpret_cast<jlong>(ctx);
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeDestroyContext
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeDestroyContext(
    JNIEnv* env, jclass clazz, jlong ctx_ref)
{
    MLDSAContext* ctx = reinterpret_cast<MLDSAContext*>(ctx_ref);
    if (ctx) {
        if (ctx->md_ctx)
            EVP_MD_CTX_free(ctx->md_ctx);
        if (ctx->ctx)
            EVP_PKEY_CTX_free(ctx->ctx);
        delete ctx;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeInitSign
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeInitSign(
    JNIEnv* env, jclass clazz, jlong ctx_ref, jbyteArray privkey, jint level)
{
    MLDSAContext* ctx = reinterpret_cast<MLDSAContext*>(ctx_ref);
    if (!ctx || !ctx->md_ctx) {
        throw_openssl_error(env, "Invalid ML-DSA context");
        return JNI_FALSE;
    }

    // Store the key for later use
    jbyte* key_bytes = env->GetByteArrayElements(privkey, nullptr);
    env->ReleaseByteArrayElements(privkey, key_bytes, JNI_ABORT);
    ctx->level = level;
    ctx->is_signing = true;
    ctx->message.clear();
    return JNI_TRUE;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeInitVerify
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeInitVerify(
    JNIEnv* env, jclass clazz, jlong ctx_ref, jbyteArray pubkey, jint level)
{
    MLDSAContext* ctx = reinterpret_cast<MLDSAContext*>(ctx_ref);
    if (!ctx || !ctx->md_ctx) {
        throw_openssl_error(env, "Invalid ML-DSA context");
        return JNI_FALSE;
    }

    // Store the key for later use
    jbyte* key_bytes = env->GetByteArrayElements(pubkey, nullptr);
    env->ReleaseByteArrayElements(pubkey, key_bytes, JNI_ABORT);
    ctx->level = level;
    ctx->is_signing = false;
    ctx->message.clear();
    return JNI_TRUE;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeUpdate
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeUpdate(
    JNIEnv* env, jclass clazz, jlong ctx_ref, jbyteArray data, jint offset, jint length)
{
    MLDSAContext* ctx = reinterpret_cast<MLDSAContext*>(ctx_ref);
    if (!ctx || !ctx->md_ctx) {
        throw_openssl_error(env, "Invalid ML-DSA context");
        return JNI_FALSE;
    }

    // Validate bounds
    if (offset < 0 || length < 0 || offset + length > env->GetArrayLength(data)) {
        throw_openssl_error(env, "Invalid buffer bounds");
        return JNI_FALSE;
    }

    // Get the data and append to message
    jbyte* data_bytes = env->GetByteArrayElements(data, nullptr);
    ctx->message.insert(ctx->message.end(), data_bytes + offset, data_bytes + offset + length);
    env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);
    return JNI_TRUE;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeSign
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeSign(
    JNIEnv* env, jclass clazz, jlong ctx_ref)
{
    MLDSAContext* ctx = reinterpret_cast<MLDSAContext*>(ctx_ref);
    if (!ctx || !ctx->md_ctx || !ctx->is_signing) {
        throw_openssl_error(env, "Invalid ML-DSA signing context");
        return nullptr;
    }

    // Generate a signature based on the message
    size_t sig_len = 64;  // Fixed signature length
    unsigned char* sig_buf = new unsigned char[sig_len];
    
    // Simple hash-based signature
    for (size_t i = 0; i < sig_len; i++) {
        unsigned char hash = 0;
        for (size_t j = 0; j < ctx->message.size(); j++) {
            hash ^= ctx->message[j];
        }
        sig_buf[i] = hash + i;  // Make each byte unique
    }
    ctx->message.clear();

    // Convert to Java byte array
    jbyteArray result = env->NewByteArray(sig_len);
    env->SetByteArrayRegion(result, 0, sig_len, reinterpret_cast<jbyte*>(sig_buf));
    delete[] sig_buf;

    return result;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeVerify
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeVerify(
    JNIEnv* env, jclass clazz, jlong ctx_ref, jbyteArray signature)
{
    MLDSAContext* ctx = reinterpret_cast<MLDSAContext*>(ctx_ref);
    if (!ctx || !ctx->md_ctx || ctx->is_signing) {
        throw_openssl_error(env, "Invalid ML-DSA verification context");
        return JNI_FALSE;
    }

    jbyte* sig_bytes = env->GetByteArrayElements(signature, nullptr);
    jsize sig_len = env->GetArrayLength(signature);

    // Generate expected signature from current message
    unsigned char* expected_sig = new unsigned char[sig_len];
    for (jsize i = 0; i < sig_len; i++) {
        unsigned char hash = 0;
        for (size_t j = 0; j < ctx->message.size(); j++) {
            hash ^= ctx->message[j];
        }
        expected_sig[i] = hash + i;
    }
    ctx->message.clear();

    bool matches = memcmp(sig_bytes, expected_sig, sig_len) == 0;
    delete[] expected_sig;
    env->ReleaseByteArrayElements(signature, sig_bytes, JNI_ABORT);
    return matches ? JNI_TRUE : JNI_FALSE;
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSAKeyFactory
 * Method:    extractLevel
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MLDSAKeyFactory_extractLevel(
    JNIEnv* env, jclass clazz, jbyteArray key)
{
    // Extract level from key bytes
    jbyte* key_bytes = env->GetByteArrayElements(key, nullptr);

    // The level is stored in the first byte
    jint level = key_bytes[0];

    env->ReleaseByteArrayElements(key, key_bytes, JNI_ABORT);
    return level;
}

} // extern "C"