// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

abstract class MLDSAKey extends EvpKey {
  private static final long serialVersionUID = 1;
  private final int level;

  MLDSAKey(final InternalKey key, final boolean isPublicKey, final int level) {
    super(key, EvpKeyType.MlDsa, isPublicKey);
    this.level = level;
  }

  public int getLevel() {
    return level;
  }
}