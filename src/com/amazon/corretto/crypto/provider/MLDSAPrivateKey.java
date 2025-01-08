// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

final class MLDSAPrivateKey implements PrivateKey {
  private static final long serialVersionUID = 1L;
  private final byte[] encoded;
  private final int level;

  MLDSAPrivateKey(final byte[] encoded, int level) throws InvalidKeySpecException {
    this.encoded = encoded.clone();
    this.level = level;
    // TODO: Add validation of encoded key format
  }

  MLDSAPrivateKey(final PKCS8EncodedKeySpec spec, int level) throws InvalidKeySpecException {
    this(spec.getEncoded(), level);
  }

  @Override
  public String getAlgorithm() {
    return "ML-DSA";
  }

  @Override
  public String getFormat() {
    return "PKCS#8";
  }

  @Override
  public byte[] getEncoded() {
    return encoded.clone();
  }

  public int getLevel() {
    return level;
  }

  @Override
  public boolean equals(final Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    MLDSAPrivateKey that = (MLDSAPrivateKey) o;
    return level == that.level && Arrays.equals(encoded, that.encoded);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(encoded);
    result = 31 * result + level;
    return result;
  }
}
