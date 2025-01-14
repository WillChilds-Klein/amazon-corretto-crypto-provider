// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PublicKey;

class MLDSAPublicKey extends MLDSAKey implements PublicKey {
  private static final long serialVersionUID = 1;

  private static native byte[] getPublicKey(long ptr);

  private volatile byte[] publicKey;

  MLDSAPublicKey(final long ptr, final int level) {
    this(new InternalKey(ptr), level);
  }

  MLDSAPublicKey(final InternalKey key, final int level) {
    super(key, true, level);
  }
}
