// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.*;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.amazon.corretto.crypto.provider.MLDSAKeyGenParameterSpec;
import java.security.*;
import java.security.spec.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class MLDSATest {
  private static final String PROVIDER_NAME = "AmazonCorrettoCryptoProvider";
  private static final String MESSAGE = "Hello, ML-DSA!";

  @BeforeAll
  public static void setUp() {
    Security.addProvider(new AmazonCorrettoCryptoProvider());
  }

  @ParameterizedTest
  @ValueSource(ints = {2, 3, 5})
  public void testKeyGeneration(int level) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", PROVIDER_NAME);
    keyGen.initialize(new MLDSAKeyGenParameterSpec(level));
    KeyPair keyPair = keyGen.generateKeyPair();

    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivate());
    assertNotNull(keyPair.getPublic());
    assertEquals("ML-DSA", keyPair.getPrivate().getAlgorithm());
    assertEquals("ML-DSA", keyPair.getPublic().getAlgorithm());
  }

  @ParameterizedTest
  @ValueSource(ints = {2, 3, 5})
  public void testSignAndVerify(int level) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", PROVIDER_NAME);
    keyGen.initialize(new MLDSAKeyGenParameterSpec(level));
    KeyPair keyPair = keyGen.generateKeyPair();

    Signature signer = Signature.getInstance("ML-DSA", PROVIDER_NAME);
    signer.initSign(keyPair.getPrivate());
    signer.update(MESSAGE.getBytes());
    byte[] signature = signer.sign();

    Signature verifier = Signature.getInstance("ML-DSA", PROVIDER_NAME);
    verifier.initVerify(keyPair.getPublic());
    verifier.update(MESSAGE.getBytes());
    assertTrue(verifier.verify(signature));
  }

  @Test
  public void testSignatureVerificationWithDifferentMessage() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", PROVIDER_NAME);
    keyGen.initialize(new MLDSAKeyGenParameterSpec(MLDSAKeyGenParameterSpec.LEVEL3));
    KeyPair keyPair = keyGen.generateKeyPair();

    Signature signer = Signature.getInstance("ML-DSA", PROVIDER_NAME);
    signer.initSign(keyPair.getPrivate());
    signer.update(MESSAGE.getBytes());
    byte[] signature = signer.sign();

    Signature verifier = Signature.getInstance("ML-DSA", PROVIDER_NAME);
    verifier.initVerify(keyPair.getPublic());
    verifier.update("Different message".getBytes());
    assertFalse(verifier.verify(signature));
  }

  @Test
  public void testKeyFactoryConversion() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", PROVIDER_NAME);
    keyGen.initialize(new MLDSAKeyGenParameterSpec(MLDSAKeyGenParameterSpec.LEVEL3));
    KeyPair originalKeyPair = keyGen.generateKeyPair();

    KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", PROVIDER_NAME);

    // Test public key conversion
    byte[] publicKeyEncoded = originalKeyPair.getPublic().getEncoded();
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
    assertArrayEquals(publicKeyEncoded, publicKey.getEncoded());

    // Test private key conversion
    byte[] privateKeyEncoded = originalKeyPair.getPrivate().getEncoded();
    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
    assertArrayEquals(privateKeyEncoded, privateKey.getEncoded());
  }

  @Test
  public void testInvalidKeyInitialization() {
    assertThrows(
        InvalidKeyException.class,
        () -> {
          KeyPair rsaKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
          Signature sig = Signature.getInstance("ML-DSA", PROVIDER_NAME);
          sig.initSign(rsaKeys.getPrivate());
        });

    assertThrows(
        InvalidKeyException.class,
        () -> {
          KeyPair rsaKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
          Signature sig = Signature.getInstance("ML-DSA", PROVIDER_NAME);
          sig.initVerify(rsaKeys.getPublic());
        });
  }
}
