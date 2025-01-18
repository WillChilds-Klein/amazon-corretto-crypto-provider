// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class MlDsaGen extends KeyPairGeneratorSpi {
  /** Generates a new MlDsa25519 key and returns a pointer to it. */
  private static native long generateEvpMlDsaKey(int nid);

  private final AmazonCorrettoCryptoProvider provider_;
  private EvpKeyType type_;

  protected MlDsaGen(AmazonCorrettoCryptoProvider provider, EvpKeyType type) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    type_ = type;
  }

  public void initialize(AlgorithmParameterSpec params, final SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  public void initialize(final int keysize, final SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  @Override
  public KeyPair generateKeyPair() {
    if (type_ == null) {
      throw new IllegalStateException("Key type not set");
    }
    long pkey_ptr = generateEvpMlDsaKey(type_.nativeValue);
    final PrivateKey privateKey = new EvpMlDsaPrivateKey(pkey_ptr, type_);
    final PublicKey publicKey = new EvpMlDsaPublicKey(pkey_ptr, type_);
    return new KeyPair(publicKey, privateKey);
  }

  public static final class MlDsaGen44 extends MlDsaGen {
    public MlDsaGen44(AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.MlDSA44);
    }
  }

  public static final class MlDsaGen65 extends MlDsaGen {
    public MlDsaGen65(AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.MlDSA65);
    }
  }

  public static final class MlDsaGen87 extends MlDsaGen {
    public MlDsaGen87(AmazonCorrettoCryptoProvider provider) {
      super(provider, EvpKeyType.MlDSA87);
    }
  }
}
