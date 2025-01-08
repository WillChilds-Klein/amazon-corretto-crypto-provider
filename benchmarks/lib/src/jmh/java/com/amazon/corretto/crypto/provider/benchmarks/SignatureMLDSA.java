// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.MLDSAKeyGenParameterSpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class SignatureMLDSA extends SignatureBase {
    @Param({AmazonCorrettoCryptoProvider.PROVIDER_NAME})
    public String provider;

    @Param({"2", "3", "5"})
    public int level;

    @Setup
    public void setup() throws Exception {
        super.setup(provider, "ML-DSA", new MLDSAKeyGenParameterSpec(level), "ML-DSA", null);
    }

    @Benchmark
    public byte[] sign() throws Exception {
        return super.sign();
    }

    @Benchmark
    public boolean verify() throws Exception {
        return super.verify();
    }
}