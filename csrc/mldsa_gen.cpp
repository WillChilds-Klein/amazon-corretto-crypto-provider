// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "env.h"
#include "generated-headers.h"
#include <openssl/evp.h>

using namespace AmazonCorrettoCryptoProvider;

JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_MlDsaGen_generateEvpMlDsaKey(
    JNIEnv* pEnv, jclass, jint level)
{
    try {
        raii_env env(pEnv);
        EVP_PKEY_auto key;
        EVP_PKEY_CTX_auto ctx = EVP_PKEY_CTX_auto::from(EVP_PKEY_CTX_new_id(EVP_PKEY_PQDSA, NULL));
        CHECK_OPENSSL(ctx.isInitialized());
        int nid = 0; // TODO [cildw] fix this with constants
        switch (level) {
        case 2:
            nid = 994;
        case 3:
            nid = 995;
        case 5:
            nid = 996;
        }
        CHECK_OPENSSL(EVP_PKEY_CTX_pqdsa_set_params(ctx, nid));
        CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx));
        CHECK_OPENSSL(EVP_PKEY_keygen(ctx, key.getAddressOfPtr()));
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
    }
    return 0;
}