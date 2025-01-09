// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "mldsa.h"
#include "env.h"
#include "keyutils.h"
#include "util.h"
#include "auto_free.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

using namespace AmazonCorrettoCryptoProvider;

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
    jobjectArray result = nullptr;

    try {
        // Validate ML-DSA level
        switch (level) {
        case 2:
        case 3:
        case 5:
            break;
        default:
            throw_openssl_error(env, "Invalid ML-DSA security level");
            return nullptr;
        }

        // Generate ML-DSA key pair

        // Set the ML-DSA parameters based on the level
        int nid;
        switch (level) {
        case 2:
            nid = NID_MLDSA44;
            break;
        case 3:
            nid = NID_MLDSA65;
            break;
        case 5:
            nid = NID_MLDSA87;
            break;
        default:
            throw_openssl_error(nullptr, "Invalid ML-DSA security level");
            return nullptr;
        }

        // Initialize CBB objects for marshaling
        CBB pub_cbb, priv_cbb;
        if (!CBB_init(&pub_cbb, 0) || !CBB_init(&priv_cbb, 0)) {
            throw_openssl_error(env, "Failed to initialize CBB");
            return nullptr;
        }

        // Create the context for key generation
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, nullptr);
        EVP_PKEY *key = nullptr;
        if (EVP_PKEY_CTX_pqdsa_set_params(ctx, nid) != 1 ||
            EVP_PKEY_keygen_init(ctx) != 1 ||
            EVP_PKEY_keygen(ctx, &key) != 1) {
            throw_openssl_error(env, "Failed init keygen and gen key");
            return nullptr;
        }

        // Marshal the keys
        if (!EVP_marshal_public_key(&pub_cbb, key) || !EVP_marshal_private_key(&priv_cbb, key)) {
            CBB_cleanup(&pub_cbb);
            CBB_cleanup(&priv_cbb);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw_openssl_error(env, "Failed to marshal ML-DSA keys");
            return nullptr;
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);

        // Marshaled the keys
        uint8_t *pub_buf = NULL, *priv_buf = NULL;
        size_t pub_len = 0, priv_len = 0;
        if (!CBB_finish(&pub_cbb, &pub_buf, &pub_len) || !CBB_finish(&priv_cbb, &priv_buf, &priv_len)) {
            CBB_cleanup(&pub_cbb);
            CBB_cleanup(&priv_cbb);
            OPENSSL_free(pub_buf);
            OPENSSL_free(priv_buf);
            throw_openssl_error(env, "Failed to finish CBB");
            return nullptr;
        }

        jbyteArray pubArray = env->NewByteArray(pub_len);
        jbyteArray privArray = env->NewByteArray(priv_len);
        if (!pubArray || !privArray) {
            OPENSSL_free(pub_buf);
            OPENSSL_free(priv_buf);
            throw_openssl_error(env, "Failed to create byte arrays");
            return nullptr;
        }

        // Create result array
        jclass byteArrayClass = env->FindClass("[B");
        if (!byteArrayClass) {
            OPENSSL_free(pub_buf);
            OPENSSL_free(priv_buf);
            throw_openssl_error(env, "Failed to find byte array class");
            return nullptr;
        }
        result = env->NewObjectArray(2, byteArrayClass, nullptr);
        if (!result) {
            OPENSSL_free(pub_buf);
            OPENSSL_free(priv_buf);
            throw_openssl_error(env, "Failed to create result array");
            return nullptr;
        }

        // Copy marshaled keys
        env->SetByteArrayRegion(pubArray, 0, pub_len, (jbyte*)pub_buf);
        env->SetByteArrayRegion(privArray, 0, priv_len, (jbyte*)priv_buf);

        OPENSSL_free(pub_buf);
        OPENSSL_free(priv_buf);

        env->SetObjectArrayElement(result, 0, pubArray);
        env->SetObjectArrayElement(result, 1, privArray);
    } catch (java_ex& ex) {
        if (result) {
            env->DeleteLocalRef(result);
            result = nullptr;
        }
        ex.throw_to_java(env);
    }

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

    // Convert private key from DER format
    jbyte* key_bytes = env->GetByteArrayElements(privkey, nullptr);
    jsize key_len = env->GetArrayLength(privkey);
    const unsigned char* key_buf = reinterpret_cast<const unsigned char*>(key_bytes + 1);  // Skip level byte
    EVP_PKEY_auto pkey = EVP_PKEY_auto::from(d2i_PrivateKey(EVP_PKEY_PQDSA, nullptr, &key_buf, key_len - 1));
    env->ReleaseByteArrayElements(privkey, key_bytes, JNI_ABORT);

    CHECK_OPENSSL(pkey.isInitialized());

    // Initialize signing operation
    CHECK_OPENSSL(EVP_DigestSignInit(ctx->md_ctx, &ctx->ctx, nullptr, nullptr, pkey) == 1);
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

    // Convert public key from DER format
    jbyte* key_bytes = env->GetByteArrayElements(pubkey, nullptr);
    jsize key_len = env->GetArrayLength(pubkey);
    const unsigned char* key_buf = reinterpret_cast<const unsigned char*>(key_bytes + 1);  // Skip level byte
    EVP_PKEY_auto pkey = EVP_PKEY_auto::from(d2i_PUBKEY(nullptr, &key_buf, key_len - 1));
    env->ReleaseByteArrayElements(pubkey, key_bytes, JNI_ABORT);

    CHECK_OPENSSL(pkey.isInitialized());

    // Initialize verification operation
    CHECK_OPENSSL(EVP_DigestVerifyInit(ctx->md_ctx, &ctx->ctx, nullptr, nullptr, pkey) == 1);
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

    // Get the data and update the digest
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

    jbyte* sig_bytes = env->GetByteArrayElements(signature, nullptr);
    jsize sig_len = env->GetArrayLength(signature);

    // Verify the signature
    int result = EVP_DigestVerifyFinal(ctx->md_ctx, reinterpret_cast<unsigned char*>(sig_bytes), sig_len);

    env->ReleaseByteArrayElements(signature, sig_bytes, JNI_ABORT);

    if (result < 0) {
        throw_openssl_error(env, "ML-DSA verification failed");
        return JNI_FALSE;
    }

    return result == 1 ? JNI_TRUE : JNI_FALSE;
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