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

std::function<void(char const*)> call_fips_callback = [](char const*) { };

// To have this symbol exported, one needs to modify the final-link.version and the CMakeLists.txt
extern "C" void AWS_LC_fips_failure_callback(char const* message);

void AWS_LC_fips_failure_callback(char const* message)
{
    fprintf(stderr, "AWS_LC_fips_failure_callback invoked with message: '%s'\n", message);
    call_fips_callback(message);
}

namespace AmazonCorrettoCryptoProvider {

extern "C" JNIEXPORT void JNICALL
Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_registerFipsCallback(JNIEnv* env, jobject thisObj)
{
    // scope in |env| pointer and a reference to |thisObj|
    call_fips_callback = [env, &thisObj](char const* message) {
        jclass thisClass = env->GetObjectClass(thisObj);
        jmethodID mid = env->GetMethodID(thisClass, "callFipsCallback", "(S)V");
        env->CallVoidMethod(thisObj, mid, message);
    };
}

extern "C" JNIEXPORT void JNICALL Java_com_amazon_corretto_crypto_provider_AmazonCorrettoCryptoProvider_initializeAwsLc(
    JNIEnv*, jobject)
{
    // TODO [childw] call AWS-LC's init() method here!
}

} // namespace
