// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

class EvpMlDsaPrivateKey extends EvpMlDsaKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  private static native byte[] encodeMlDsaPrivateKey(long ptr);

  EvpMlDsaPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpMlDsaPrivateKey(final InternalKey key) {
    super(key, false);
  }

  public EvpMlDsaPublicKey getPublicKey() {
    this.ephemeral = false;
    this.sharedKey = true;
    final EvpMlDsaPublicKey result = new EvpMlDsaPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }

  @Override
  protected byte[] internalGetEncoded() {
    // ML-DSA private keys have special logic to handle presence/absence of seed
    assertNotDestroyed();
    byte[] result = encoded;
    if (result == null) {
      synchronized (this) {
        result = encoded;
        if (result == null) {
          result = use(EvpMlDsaPrivateKey::encodeMlDsaPrivateKey);
          encoded = result;
        }
      }
    }
    return result;
  }
}
