// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.*;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class MlDSATest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
  // TODO [childw] parameterize keygen algo + message size
  // private static String[] MLDSA_KEYGEN_ALGOS = new String {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
  private static final byte[] MESSAGE = {0x01, 0x02, 0x03, 0x04};

  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testKeyGeneration(String algo) throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algo, NATIVE_PROVIDER);
    KeyPair keyPair = keyGen.generateKeyPair();

    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivate());
    assertNotNull(keyPair.getPublic());
    assertEquals("ML-DSA", keyPair.getPrivate().getAlgorithm());
    assertEquals("ML-DSA", keyPair.getPublic().getAlgorithm());
  }

  @Test
  public void testKeyFactoryConversion() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    KeyPair originalKeyPair = keyGen.generateKeyPair();

    KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER);

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
          Signature sig = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
          sig.initSign(rsaKeys.getPrivate());
        });

    assertThrows(
        InvalidKeyException.class,
        () -> {
          KeyPair rsaKeys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
          Signature sig = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);
          sig.initVerify(rsaKeys.getPublic());
        });
  }

  @ParameterizedTest
  @ValueSource(strings = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
  public void testRoundTrips(String algo) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance(algo, NATIVE_PROVIDER).generateKeyPair();
    PublicKey nativePub = keyPair.getPublic();
    PrivateKey nativePriv = keyPair.getPrivate();

    // Convert ACCP native key to BouncyCastle key
    KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
    PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));

    Signature bcSig = Signature.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
    Signature nativeSig = Signature.getInstance("ML-DSA", NATIVE_PROVIDER);

    // BouncyCastle -> BouncyCastle (bad signature)
    bcSig.initSign(bcPriv);
    bcSig.update(MESSAGE);
    byte[] sigBytes = bcSig.sign();
    bcSig.initVerify(bcPub);
    bcSig.update(MESSAGE);
    assertTrue(bcSig.verify(sigBytes));

    // ACCP -> ACCP (bad signature)
    nativeSig.initSign(nativePriv);
    nativeSig.update(MESSAGE);
    sigBytes = nativeSig.sign();
    nativeSig.initVerify(nativePub);
    nativeSig.update(MESSAGE);
    assertTrue(nativeSig.verify(sigBytes));

    // BouncyCastle -> ACCP (good signature)
    bcSig.initSign(bcPriv);
    bcSig.update(MESSAGE);
    sigBytes = bcSig.sign();
    nativeSig.initVerify(nativePub);
    nativeSig.update(MESSAGE);
    assertTrue(nativeSig.verify(sigBytes));

    // ACCP -> BouncyCastle (good signature)
    nativeSig.initSign(nativePriv);
    nativeSig.update(MESSAGE);
    sigBytes = nativeSig.sign();
    bcSig.initVerify(bcPub);
    bcSig.update(MESSAGE);
    assertTrue(bcSig.verify(sigBytes));

    // BouncyCastle -> BouncyCastle (bad signature)
    bcSig.initSign(bcPriv);
    bcSig.update(MESSAGE);
    sigBytes = bcSig.sign();
    bcSig.initVerify(bcPub);
    bcSig.update("Different message".getBytes());
    assertFalse(bcSig.verify(sigBytes));

    // ACCP -> ACCP (bad signature)
    nativeSig.initSign(nativePriv);
    nativeSig.update(MESSAGE);
    sigBytes = nativeSig.sign();
    nativeSig.initVerify(nativePub);
    nativeSig.update("Different message".getBytes());
    assertFalse(nativeSig.verify(sigBytes));

    // BouncyCastle -> ACCP (bad signature)
    bcSig.initSign(bcPriv);
    bcSig.update(MESSAGE);
    sigBytes = bcSig.sign();
    nativeSig.initVerify(nativePub);
    nativeSig.update("Different message".getBytes());
    assertFalse(nativeSig.verify(sigBytes));

    // ACCP -> BouncyCastle (bad signature)
    nativeSig.initSign(nativePriv);
    nativeSig.update(MESSAGE);
    sigBytes = nativeSig.sign();
    bcSig.initVerify(bcPub);
    bcSig.update("Different message".getBytes());
    assertFalse(bcSig.verify(sigBytes));
  }
}
