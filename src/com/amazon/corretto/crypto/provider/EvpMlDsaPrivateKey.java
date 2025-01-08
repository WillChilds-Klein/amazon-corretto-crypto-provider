// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.PrivateKey;

class EvpMlDsaPrivateKey extends EvpMlDsaKey implements PrivateKey {
  private static final long serialVersionUID = 1L;

  EvpMlDsaPrivateKey(final InternalKey key) {
    super(key, false);
  }

  EvpMlDsaPublicKey getPublic() {
    final EvpMlDsaPublicKey result = new EvpMlDsaPublicKey(internalKey);
    ephemeral = false;
    sharedKey = true;
    result.sharedKey = true;
    return result;
  }
}
