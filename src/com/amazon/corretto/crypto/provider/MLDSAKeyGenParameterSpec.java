// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

public class MLDSAKeyGenParameterSpec implements AlgorithmParameterSpec {
  public static final int LEVEL2 = 2;
  public static final int LEVEL3 = 3;
  public static final int LEVEL5 = 5;

  private final int level;

  public MLDSAKeyGenParameterSpec(int level) {
    if (level != LEVEL2 && level != LEVEL3 && level != LEVEL5) {
      throw new IllegalArgumentException("Invalid ML-DSA security level. Must be 2, 3, or 5.");
    }
    this.level = level;
  }

  public int getLevel() {
    return level;
  }
}
