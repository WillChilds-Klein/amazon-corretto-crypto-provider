// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

class MlDsaGen extends KeyPairGeneratorSpi {
  private final int mlDsaNid;

  MlDsaGen(final int mlDsaNid) {
    this.mlDsaNid = mlDsaNid;
  }

  @Override
  public void initialize(final int keysize, final SecureRandom random) {
    throw new UnsupportedOperationException("");
  }

  @Override
  public KeyPair generateKeyPair() {
    final EvpMlDsaPrivateKey privateKey =
        new EvpMlDsaPrivateKey(new EvpKey.InternalKey(nGenerateMlDsaKeyPair(mlDsaNid)));
    final EvpMlDsaPublicKey publicKey = privateKey.getPublic();
    return new KeyPair(publicKey, privateKey);
  }

  private static native long nGenerateMlDsaKeyPair(int nid);
}
