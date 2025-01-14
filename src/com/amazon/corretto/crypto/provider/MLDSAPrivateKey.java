// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

class MLDSAPrivateKey extends MLDSAKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  private static native byte[] getPrivateKey(long ptr);

  private volatile byte[] privateKey;

  MLDSAPrivateKey(final long ptr, final int level) {
    this(new InternalKey(ptr), level);
  }

  MLDSAPrivateKey(final InternalKey key, final int level) {
    super(key, false, level);
  }

  public MLDSAPublicKey getPublicKey() {
    ephemeral = false;
    sharedKey = true;
    final MLDSAPublicKey result = new MLDSAPublicKey(internalKey, getLevel());
    result.sharedKey = true;
    return result;
  }
}
