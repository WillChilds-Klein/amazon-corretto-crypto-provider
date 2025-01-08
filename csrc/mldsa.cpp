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
        // Create ML-DSA context
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, nullptr);
        if (!ctx) {
            throw_openssl_error(env, "Failed to create ML-DSA context");
            return nullptr;
        }

        // Map Java level to NID
        int pqdsa_nid;
        switch (level) {
        case 2:
            pqdsa_nid = NID_MLDSA44;
            break;
        case 3:
            pqdsa_nid = NID_MLDSA65;
            break;
        case 5:
            pqdsa_nid = NID_MLDSA87;
            break;
        default:
            throw_openssl_error(env, "Invalid ML-DSA security level");
            goto cleanup;
        }

        // Set ML-DSA parameters
        if (!EVP_PKEY_CTX_pqdsa_set_params(ctx, pqdsa_nid)) {
            throw_openssl_error(env, "Failed to set ML-DSA parameters");
            goto cleanup;
        }

        // Initialize key generation
        if (!EVP_PKEY_keygen_init(ctx)) {
            throw_openssl_error(env, "Failed to initialize ML-DSA key generation");
            goto cleanup;
        }

        // Generate key pair
        if (!EVP_PKEY_keygen(ctx, &pkey)) {
            throw_openssl_error(env, "Failed to generate ML-DSA key pair");
            goto cleanup;
        }

        // Extract public and private key in DER format
        int pub_len = i2d_PUBKEY(pkey, nullptr);
        int priv_len = i2d_PrivateKey(pkey, nullptr);

        if (pub_len <= 0 || priv_len <= 0) {
            throw_openssl_error(env, "Failed to determine ML-DSA key lengths");
            goto cleanup;
        }

        unsigned char* pub_buf = new unsigned char[pub_len];
        unsigned char* priv_buf = new unsigned char[priv_len];
        unsigned char* pub_tmp = pub_buf;
        unsigned char* priv_tmp = priv_buf;

        if (i2d_PUBKEY(pkey, &pub_tmp) != pub_len || i2d_PrivateKey(pkey, &priv_tmp) != priv_len) {
            delete[] pub_buf;
            delete[] priv_buf;
            throw_openssl_error(env, "Failed to encode ML-DSA keys");
            goto cleanup;
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

cleanup:
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

    // Convert private key from DER format
    jsize key_len = env->GetArrayLength(privkey);
    jbyte* key_bytes = env->GetByteArrayElements(privkey, nullptr);
    const unsigned char* key_buf = reinterpret_cast<const unsigned char*>(key_bytes);
    EVP_PKEY* pkey = d2i_PrivateKey(EVP_PKEY_PQDSA, nullptr, &key_buf, key_len);
    env->ReleaseByteArrayElements(privkey, key_bytes, JNI_ABORT);

    if (!pkey) {
        throw_openssl_error(env, "Failed to decode ML-DSA private key");
        return JNI_FALSE;
    }

    // Initialize signing operation
    if (!EVP_DigestSignInit(ctx->md_ctx, &ctx->ctx, EVP_sha3_384(), nullptr, pkey)) {
        EVP_PKEY_free(pkey);
        throw_openssl_error(env, "Failed to initialize ML-DSA signing operation");
        return JNI_FALSE;
    }

    EVP_PKEY_free(pkey);
    ctx->level = level;
    ctx->is_signing = true;
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

    // Convert public key from DER format
    jsize key_len = env->GetArrayLength(pubkey);
    jbyte* key_bytes = env->GetByteArrayElements(pubkey, nullptr);
    const unsigned char* key_buf = reinterpret_cast<const unsigned char*>(key_bytes);
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &key_buf, key_len);
    env->ReleaseByteArrayElements(pubkey, key_bytes, JNI_ABORT);

    if (!pkey) {
        throw_openssl_error(env, "Failed to decode ML-DSA public key");
        return JNI_FALSE;
    }

    // Initialize verification operation
    if (!EVP_DigestVerifyInit(ctx->md_ctx, &ctx->ctx, EVP_sha3_384(), nullptr, pkey)) {
        EVP_PKEY_free(pkey);
        throw_openssl_error(env, "Failed to initialize ML-DSA verification operation");
        return JNI_FALSE;
    }

    EVP_PKEY_free(pkey);
    ctx->level = level;
    ctx->is_signing = false;
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

    if (offset < 0 || length < 0 || offset + length > env->GetArrayLength(data)) {
        throw_openssl_error(env, "Invalid buffer bounds");
        return JNI_FALSE;
    }

    jbyte* data_bytes = env->GetByteArrayElements(data, nullptr);
    int result;
    if (ctx->is_signing) {
        result = EVP_DigestSignUpdate(ctx->md_ctx, data_bytes + offset, length);
    } else {
        result = EVP_DigestVerifyUpdate(ctx->md_ctx, data_bytes + offset, length);
    }
    env->ReleaseByteArrayElements(data, data_bytes, JNI_ABORT);

    if (result <= 0) {
        throw_openssl_error(env, "Failed to update ML-DSA operation");
        return JNI_FALSE;
    }

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

    // First call to get signature length
    size_t sig_len;
    if (EVP_DigestSignFinal(ctx->md_ctx, nullptr, &sig_len) <= 0) {
        throw_openssl_error(env, "Failed to determine ML-DSA signature length");
        return nullptr;
    }

    // Allocate buffer and generate signature
    unsigned char* sig_buf = new unsigned char[sig_len];
    if (EVP_DigestSignFinal(ctx->md_ctx, sig_buf, &sig_len) <= 0) {
        delete[] sig_buf;
        throw_openssl_error(env, "Failed to generate ML-DSA signature");
        return nullptr;
    }

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

    jsize sig_len = env->GetArrayLength(signature);
    jbyte* sig_bytes = env->GetByteArrayElements(signature, nullptr);

    int result = EVP_DigestVerifyFinal(ctx->md_ctx, reinterpret_cast<unsigned char*>(sig_bytes), sig_len);

    env->ReleaseByteArrayElements(signature, sig_bytes, JNI_ABORT);

    if (result < 0) {
        throw_openssl_error(env, "ML-DSA verification failed");
        return JNI_FALSE;
    }

    return result == 1 ? JNI_TRUE : JNI_FALSE;
}

} // extern "C"