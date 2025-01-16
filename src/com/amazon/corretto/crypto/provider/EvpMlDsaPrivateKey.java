// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;
import java.util.Optional;

class EvpMlDsaPrivateKey extends EvpMlDsaKey implements PrivateKey {
  private static final long serialVersionUID = 1;

  private static native byte[] getPrivateKey(long ptr);

  private volatile byte[] privateKey;

  EvpMlDsaPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  EvpMlDsaPrivateKey(final InternalKey key) {
    super(key, false);
  }

  public EvpMlDsaPublicKey getPublicKey() {
    ephemeral = false;
    sharedKey = true;
    final EvpMlDsaPublicKey result = new EvpMlDsaPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }

  public Optional<byte[]> getBytes() {
    byte[] bytes = privateKey;
    if (bytes == null) {
      synchronized (this) {
        bytes = privateKey;
        if (bytes == null) {
          bytes = use(EvpMlDsaPrivateKey::getPrivateKey);
          privateKey = bytes;
        }
      }
    }
    return Optional.ofNullable(bytes);
  }
}
