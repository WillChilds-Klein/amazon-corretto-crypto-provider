// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

final class MLDSASignature extends EvpSignatureMlDsa {
  MLDSASignature(AmazonCorrettoCryptoProvider provider) {
    super(provider, MLDSAKeyGenParameterSpec.LEVEL3);
  }
}
