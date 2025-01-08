// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.*;
import java.security.spec.*;

final class MLDSAKeyFactory extends KeyFactorySpi {
  @Override
  protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof X509EncodedKeySpec) {
      // Extract level from encoded key
      int level = extractLevel(((X509EncodedKeySpec) keySpec).getEncoded());
      return new MLDSAPublicKey((X509EncodedKeySpec) keySpec, level);
    }
    throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass());
  }

  @Override
  protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
    if (keySpec instanceof PKCS8EncodedKeySpec) {
      // Extract level from encoded key
      int level = extractLevel(((PKCS8EncodedKeySpec) keySpec).getEncoded());
      return new MLDSAPrivateKey((PKCS8EncodedKeySpec) keySpec, level);
    }
    throw new InvalidKeySpecException("Unsupported key specification: " + keySpec.getClass());
  }

  @Override
  protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
      throws InvalidKeySpecException {
    if (key instanceof MLDSAPublicKey) {
      if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
        return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
      }
    } else if (key instanceof MLDSAPrivateKey) {
      if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
        return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
      }
    }
    throw new InvalidKeySpecException("Unsupported key specification: " + keySpec);
  }

  @Override
  protected Key engineTranslateKey(Key key) throws InvalidKeyException {
    if (key instanceof MLDSAPublicKey || key instanceof MLDSAPrivateKey) {
      return key;
    }
    throw new InvalidKeyException("Key must be an instance of MLDSAPublicKey or MLDSAPrivateKey");
  }

  private static native int extractLevel(byte[] encoded);

  static {
    Loader.load();
  }
}
