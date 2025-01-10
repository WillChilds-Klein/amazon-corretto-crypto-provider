// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef AMAZON_CORRETTO_CRYPTO_PROVIDER_MLDSA_H
#define AMAZON_CORRETTO_CRYPTO_PROVIDER_MLDSA_H

#include <openssl/err.h>
#include <openssl/evp.h>
#include <jni.h>
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
 * Signature: (I)[J
 */
JNIEXPORT jlongArray JNICALL Java_com_amazon_corretto_crypto_provider_MLDSAKeyPairGenerator_nativeGenerateKeyPair(
    JNIEnv*, jclass, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpSignatureMlDsa
 * Method:    signRaw
 * Signature: (JIJILjava/lang/String;II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureMlDsa_signRaw(
    JNIEnv*, jclass, jlong, jint, jlong, jint, jbyteArray, jint, jint);

/*
 * Class:     com_amazon_corretto_crypto_provider_EvpSignatureMlDsa
 * Method:    verifyRaw
 * Signature: (JIJILjava/lang/String;II[BII)Z
 */
JNIEXPORT jboolean JNICALL Java_com_amazon_corretto_crypto_provider_EvpSignatureMlDsa_verifyRaw(
    JNIEnv*, jclass, jlong, jint, jlong, jint, jbyteArray, jint, jint, jbyteArray, jint, jint);

#ifdef __cplusplus
}
#endif
#endif // AMAZON_CORRETTO_CRYPTO_PROVIDER_MLDSA_H