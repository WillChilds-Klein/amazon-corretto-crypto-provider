// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "mldsa.h"
#include "env.h"
#include "keyutils.h"
#include "util.h"
#include "auto_free.h"
#include "buffer.h"
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
JNIEXPORT jlongArray JNICALL Java_com_amazon_corretto_crypto_provider_MLDSAKeyPairGenerator_nativeGenerateKeyPair(
    JNIEnv* env, jclass clazz, jint level)
{
    jlongArray result = nullptr;

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

        // Create the context for key generation
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, nullptr);
        EVP_PKEY *key = nullptr;
        if (EVP_PKEY_CTX_pqdsa_set_params(ctx, nid) != 1 ||
            EVP_PKEY_keygen_init(ctx) != 1 ||
            EVP_PKEY_keygen(ctx, &key) != 1) {
            throw_openssl_error(env, "Failed init keygen and gen key");
            return nullptr;
        }

        // Create result array
        result = env->NewLongArray(2);
        if (!result) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(key);
            throw_openssl_error(env, "Failed to create result array");
            return nullptr;
        }

        // Use the same key for both public and private parts
        jlong keys[2] = {reinterpret_cast<jlong>(key), reinterpret_cast<jlong>(key)};
        env->SetLongArrayRegion(result, 0, 2, keys);

        EVP_PKEY_CTX_free(ctx);
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
 * Class:     com_amazon_corretto_crypto_provider_EvpSignatureMlDsa
 * Method:    signRaw
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureMlDsa_signRaw(
    JNIEnv* env, jclass clazz, jlong privateKey, jint paddingType, jlong mgfMd, jint saltLen,
    jbyteArray message, jint offset, jint length)
{
    try {
        raii_env renv(env);
        EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(privateKey);

        // Create a new context for signing
        EVP_MD_CTX_auto mdctx = EVP_MD_CTX_auto::from(EVP_MD_CTX_new());
        EVP_PKEY_CTX* pctx = nullptr;

        // Initialize signing operation
        if (EVP_DigestSignInit(mdctx, &pctx, nullptr, nullptr, pkey) <= 0) {
            throw_openssl("Failed to initialize ML-DSA signing");
        }

        // Get the message data
        java_buffer message_buf = java_buffer::from_array(renv, message, offset, length);
        jni_borrow message_borrow(renv, message_buf, "message");
        const unsigned char* msg_data = reinterpret_cast<const unsigned char*>(message_borrow.data());

        // First call to get signature length
        size_t sig_len;
        if (EVP_DigestSign(mdctx, nullptr, &sig_len, msg_data, length) <= 0) {
            throw_openssl("Failed to determine ML-DSA signature length");
        }

        // Allocate buffer and generate signature
        std::vector<unsigned char> sig_buf(sig_len);
        if (EVP_DigestSign(mdctx, sig_buf.data(), &sig_len, msg_data, length) <= 0) {
            throw_openssl("Failed to generate ML-DSA signature");
        }

        // Convert to Java byte array
        jbyteArray result = env->NewByteArray(sig_len);
        env->SetByteArrayRegion(result, 0, sig_len, reinterpret_cast<jbyte*>(sig_buf.data()));

        return result;
    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return nullptr;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpSignatureMlDsa
 * Method:    verifyRaw
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureMlDsa_verifyRaw(
    JNIEnv* env, jclass clazz, jlong publicKey, jint paddingType, jlong mgfMd, jint saltLen,
    jbyteArray message, jint offset, jint length, jbyteArray signature, jint sigOffset, jint sigLen)
{
    try {
        raii_env renv(env);
        EVP_PKEY* pkey = reinterpret_cast<EVP_PKEY*>(publicKey);

        // Create a new context for verification
        EVP_MD_CTX_auto mdctx = EVP_MD_CTX_auto::from(EVP_MD_CTX_new());
        EVP_PKEY_CTX* pctx = nullptr;

        // Initialize verification operation
        if (EVP_DigestVerifyInit(mdctx, &pctx, nullptr, nullptr, pkey) <= 0) {
            throw_openssl("Failed to initialize ML-DSA verification");
        }

        // Get the message and signature data
        java_buffer message_buf = java_buffer::from_array(renv, message, offset, length);
        java_buffer signature_buf = java_buffer::from_array(renv, signature, sigOffset, sigLen);
        jni_borrow message_borrow(renv, message_buf, "message");
        jni_borrow signature_borrow(renv, signature_buf, "signature");

        const unsigned char* msg_data = reinterpret_cast<const unsigned char*>(message_borrow.data());
        const unsigned char* sig_data = reinterpret_cast<const unsigned char*>(signature_borrow.data());

        // Verify the signature
        int result = EVP_DigestVerify(mdctx, sig_data, sigLen, msg_data, length);

        if (result < 0) {
            throw_openssl("ML-DSA verification failed");
        }

        return result == 1 ? JNI_TRUE : JNI_FALSE;
    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return JNI_FALSE;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSAKeyFactory
 * Method:    extractLevel
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_MLDSAKeyFactory_extractLevel(
    JNIEnv* env, jclass clazz, jbyteArray key)
{
    try {
        raii_env renv(env);
        java_buffer key_buf = java_buffer::from_array(renv, key, 0, env->GetArrayLength(key));
        jni_borrow key_borrow(renv, key_buf, "key");
        const unsigned char* key_data = reinterpret_cast<const unsigned char*>(key_borrow.data());
        size_t key_len = key_borrow.len();

        // Parse the key to get the NID
        EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &key_data, key_len);
        if (!pkey) {
            // Try private key
            key_data = reinterpret_cast<const unsigned char*>(key_borrow.data());
            pkey = d2i_PrivateKey(EVP_PKEY_PQDSA, nullptr, &key_data, key_len);
        }

        if (!pkey) {
            throw_openssl("Failed to parse key");
        }

        // Get the key type
        int type = EVP_PKEY_base_id(pkey);
        if (type != EVP_PKEY_PQDSA) {
            EVP_PKEY_free(pkey);
            throw_openssl("Not an ML-DSA key");
            return 0;
        }

        // Get the key parameters
        const unsigned char* p = key_data;
        const unsigned char* end = p + key_len;

        // Skip the SEQUENCE header
        int tag, xclass;
        long len;
        if (ASN1_get_object(&p, &len, &tag, &xclass, end - p) != V_ASN1_CONSTRUCTED ||
            tag != V_ASN1_SEQUENCE) {
            EVP_PKEY_free(pkey);
            throw_openssl("Invalid key format");
            return 0;
        }

        // Skip the BIT STRING header
        if (ASN1_get_object(&p, &len, &tag, &xclass, end - p) != V_ASN1_CONSTRUCTED ||
            tag != V_ASN1_SEQUENCE) {
            EVP_PKEY_free(pkey);
            throw_openssl("Invalid key format");
            return 0;
        }

        // Get the OID
        ASN1_OBJECT* obj = nullptr;
        if (d2i_ASN1_OBJECT(&obj, &p, len) == nullptr) {
            EVP_PKEY_free(pkey);
            throw_openssl("Invalid key format");
            return 0;
        }

        // Get the NID from the OID and try to get the level from it
        int level = 0;
        char oid_buf[256];
        OBJ_obj2txt(oid_buf, sizeof(oid_buf), obj, 1);
        if (strstr(oid_buf, "1.3.6.1.4.1.2.267.12.4.4") != nullptr) {
            level = 2;
        } else if (strstr(oid_buf, "1.3.6.1.4.1.2.267.12.6.5") != nullptr) {
            level = 3;
        } else if (strstr(oid_buf, "1.3.6.1.4.1.2.267.12.8.7") != nullptr) {
            level = 5;
        }
        ASN1_OBJECT_free(obj);

        // If we couldn't get the level from the OID, try to get it from the key parameters
        if (level == 0) {
            // Skip the NULL parameter
            if (ASN1_get_object(&p, &len, &tag, &xclass, end - p) < 0 ||
                tag != V_ASN1_NULL) {
                EVP_PKEY_free(pkey);
                throw_openssl("Invalid key format");
                return 0;
            }

            // Skip the BIT STRING header
            if (ASN1_get_object(&p, &len, &tag, &xclass, end - p) < 0 ||
                tag != V_ASN1_BIT_STRING) {
                EVP_PKEY_free(pkey);
                throw_openssl("Invalid key format");
                return 0;
            }

            // Skip the unused bits byte
            if (p >= end) {
                EVP_PKEY_free(pkey);
                throw_openssl("Invalid key format");
                return 0;
            }
            p++;

            // Try to determine the level from the key size
            size_t key_size = end - p;
            if (key_size >= 1312 && key_size <= 1312 + 64) {
                level = 2;
            } else if (key_size >= 2336 && key_size <= 2336 + 64) {
                level = 3;
            } else if (key_size >= 3616 && key_size <= 3616 + 64) {
                level = 5;
            }

            // If we still couldn't determine the level, try to get it from the key type
            if (level == 0) {
                int key_type = EVP_PKEY_id(pkey);
                switch (key_type) {
                case NID_MLDSA44:
                    level = 2;
                    break;
                case NID_MLDSA65:
                    level = 3;
                    break;
                case NID_MLDSA87:
                    level = 5;
                    break;
                }
            }

            // If we still couldn't determine the level, try to get it from the key parameters
            if (level == 0) {
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
                if (ctx) {
                    if (EVP_PKEY_paramgen_init(ctx) == 1) {
                        if (EVP_PKEY_CTX_pqdsa_set_params(ctx, NID_MLDSA44) == 1) {
                            level = 2;
                        } else if (EVP_PKEY_CTX_pqdsa_set_params(ctx, NID_MLDSA65) == 1) {
                            level = 3;
                        } else if (EVP_PKEY_CTX_pqdsa_set_params(ctx, NID_MLDSA87) == 1) {
                            level = 5;
                        }
                    }
                    EVP_PKEY_CTX_free(ctx);
                }
            }
        }

        EVP_PKEY_free(pkey);

        if (level == 0) {
            throw_openssl("Invalid ML-DSA level");
        }
        return level;
    } catch (java_ex& ex) {
        ex.throw_to_java(env);
        return 0;
    }
}

} // extern "C"