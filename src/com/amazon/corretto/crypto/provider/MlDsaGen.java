// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class MlDsaGen extends KeyPairGeneratorSpi {
  /** Generates a new MlDsa25519 key and returns a pointer to it. */
  private static native long generateEvpMlDsaKey();

  private final AmazonCorrettoCryptoProvider provider_;
  private final KeyFactory kf;

  MlDsaGen(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
    try {
      kf = KeyFactory.getInstance("MlDsaDSA", "SunEC");
    } catch (final GeneralSecurityException e) {
      throw new RuntimeException("Error setting up KeyPairGenerator", e);
    }
  }

  public void initialize(final int keysize, final SecureRandom random) {
    throw new UnsupportedOperationException();
  }

  @Override
  public KeyPair generateKeyPair() {
    final EvpMlDsaPrivateKey privateKey;
    final EvpMlDsaPublicKey publicKey;
    privateKey = new EvpMlDsaPrivateKey(generateEvpMlDsaKey());
    publicKey = privateKey.getPublicKey();
    try {
      final PKCS8EncodedKeySpec privateKeyPkcs8 = new PKCS8EncodedKeySpec(privateKey.getEncoded());
      final X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKey.getEncoded());
      final PrivateKey jcePrivateKey = kf.generatePrivate(privateKeyPkcs8);
      final PublicKey jcePublicKey = kf.generatePublic(publicKeyX509);
      return new KeyPair(jcePublicKey, jcePrivateKey);
    } catch (final GeneralSecurityException e) {
      throw new RuntimeException("Error generating key pair", e);
    }
  }
}
