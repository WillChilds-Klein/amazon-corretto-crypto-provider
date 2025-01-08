// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef AMAZON_CORRETTO_CRYPTO_PROVIDER_MLDSA_H
#define AMAZON_CORRETTO_CRYPTO_PROVIDER_MLDSA_H

#include <openssl/err.h>
#include <openssl/evp.h>
#include <jni.h>

// ML-DSA constants
#define EVP_PKEY_PQDSA NID_PQDSA
#define NID_MLDSA44    994
#define NID_MLDSA65    995
#define NID_MLDSA87    996

// Function declarations
int EVP_PKEY_CTX_pqdsa_set_params(EVP_PKEY_CTX* ctx, int nid);

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSAKeyPairGenerator
 * Method:    nativeGenerateKeyPair
 * Signature: (I)[[B
 */
JNIEXPORT jobjectArray JNICALL Java_com_amazon_corretto_crypto_provider_MLDSAKeyPairGenerator_nativeGenerateKeyPair(
    JNIEnv*, jclass, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeCreateContext
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeCreateContext(JNIEnv*, jclass);

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeDestroyContext
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeDestroyContext(
    JNIEnv*, jclass, jlong);

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeInitSign
 * Signature: (J[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeInitSign(
    JNIEnv*, jclass, jlong, jbyteArray, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeInitVerify
 * Signature: (J[BI)Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeInitVerify(
    JNIEnv*, jclass, jlong, jbyteArray, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeUpdate
 * Signature: (J[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeUpdate(
    JNIEnv*, jclass, jlong, jbyteArray, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeSign
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeSign(JNIEnv*, jclass, jlong);

/*
 * Class:     com_amazon_corretto_crypto_provider_MLDSASignature
 * Method:    nativeVerify
 * Signature: (J[B)Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_MLDSASignature_nativeVerify(
    JNIEnv*, jclass, jlong, jbyteArray);

#ifdef __cplusplus
}
#endif
#endif // AMAZON_CORRETTO_CRYPTO_PROVIDER_MLDSA_H