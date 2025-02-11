// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "generated-headers.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <stddef.h>
#include <string>

#include "env.h"
#include "util.h"

#define CLASSNOTFOUND_TYPE "java/lang/NoClassDefFoundError"

namespace AmazonCorrettoCryptoProvider {

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_(i JNIEnv*, jclass, jlong ctxPtr)
{
    EVP_CIPHER_CTX_free(reinterpret_cast<EVP_CIPHER_CTX*>(ctxPtr));
}

} // namespace
