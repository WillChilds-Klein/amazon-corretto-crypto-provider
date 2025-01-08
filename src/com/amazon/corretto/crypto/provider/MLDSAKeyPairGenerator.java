// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

final class MLDSAKeyPairGenerator extends KeyPairGeneratorSpi {
  private boolean initialized = false;
  private int level = MLDSAKeyGenParameterSpec.LEVEL3; // Default to level 3

  @Override
  public void initialize(int keysize, SecureRandom random) {
    // ML-DSA doesn't use keysize directly, but we can map it to security levels
    if (keysize <= 128) {
      level = MLDSAKeyGenParameterSpec.LEVEL2;
    } else if (keysize <= 192) {
      level = MLDSAKeyGenParameterSpec.LEVEL3;
    } else {
      level = MLDSAKeyGenParameterSpec.LEVEL5;
    }
    initialized = true;
  }

  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof MLDSAKeyGenParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "Parameters must be an instance of MLDSAKeyGenParameterSpec");
    }
    level = ((MLDSAKeyGenParameterSpec) params).getLevel();
    initialized = true;
  }

  @Override
  public KeyPair generateKeyPair() {
    if (!initialized) {
      // Use default parameters if not initialized
      initialized = true;
    }

    try {
      // Call native method to generate key pair
      byte[][] keyPair = nativeGenerateKeyPair(level);
      return new KeyPair(
          new MLDSAPublicKey(keyPair[0], level), new MLDSAPrivateKey(keyPair[1], level));
    } catch (InvalidKeySpecException e) {
      throw new ProviderException("Failed to generate ML-DSA key pair", e);
    }
  }

  private static native byte[][] nativeGenerateKeyPair(int level);

  static {
    Loader.load();
  }
}
