// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

@Execution(ExecutionMode.CONCURRENT)
@ExtendWith(TestResultLogger.class)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class MlDSATest {
  private static final Provider NATIVE_PROVIDER = AmazonCorrettoCryptoProvider.INSTANCE;
  private static final int[] MESSAGE_LENGTHS = new int[] {0, 1, 16, 32, 2047, 2048, 2049, 4100};

  private static class TestParams {
    private final Provider signerProv;
    private final Provider verifierProv;
    private final PrivateKey priv;
    private final PublicKey pub;
    private final byte[] signMessage;
    private final byte[] verifyMessage;

    public TestParams(
        Provider signerProv,
        Provider verifierProv,
        PrivateKey priv,
        PublicKey pub,
        byte[] signMessage,
        byte[] verifyMessage) {
      this.signerProv = signerProv;
      this.verifierProv = verifierProv;
      this.priv = priv;
      this.pub = pub;
      this.signMessage = signMessage;
      this.verifyMessage = verifyMessage;
    }

    public String toString() {
      return String.format(
          "signer: %s, verifier: %s, message size: %d, messsages equal: %s",
          signerProv.getName(),
          verifierProv.getName(),
          signMessage.length,
          Arrays.equals(signMessage, verifyMessage));
    }
  }

  private static List<TestParams> getParams() throws Exception {
    List<TestParams> params = new ArrayList<TestParams>();
    for (String algo : new String[] {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}) {
      for (int messageSize : MESSAGE_LENGTHS) {
        KeyPair keyPair = KeyPairGenerator.getInstance(algo, NATIVE_PROVIDER).generateKeyPair();
        PublicKey nativePub = keyPair.getPublic();
        PrivateKey nativePriv = keyPair.getPrivate();

        // Convert ACCP native key to BouncyCastle key
        KeyFactory bcKf = KeyFactory.getInstance("ML-DSA", TestUtil.BC_PROVIDER);
        PublicKey bcPub = bcKf.generatePublic(new X509EncodedKeySpec(nativePub.getEncoded()));
        PrivateKey bcPriv = bcKf.generatePrivate(new PKCS8EncodedKeySpec(nativePriv.getEncoded()));

        Provider nativeProv = NATIVE_PROVIDER;
        Provider bcProv = TestUtil.BC_PROVIDER;

        byte[] m1 = new byte[messageSize];
        Arrays.fill(m1, (byte) 'A');
        byte[] m2 = new byte[messageSize];
        Arrays.fill(m2, (byte) 'B');

        // Verification success
        params.add(new TestParams(nativeProv, nativeProv, nativePriv, nativePub, m1, m1));
        params.add(new TestParams(nativeProv, bcProv, nativePriv, bcPub, m1, m1));
        params.add(new TestParams(bcProv, nativeProv, bcPriv, nativePub, m1, m1));
        params.add(new TestParams(bcProv, bcProv, bcPriv, bcPub, m1, m1));

        // Verification failure
        params.add(new TestParams(nativeProv, nativeProv, nativePriv, nativePub, m1, m2));
        params.add(new TestParams(nativeProv, bcProv, nativePriv, bcPub, m1, m2));
        params.add(new TestParams(bcProv, nativeProv, bcPriv, nativePub, m1, m2));
        params.add(new TestParams(bcProv, bcProv, bcPriv, bcPub, m1, m2));
      }
    }
    return params;
  }

  @ParameterizedTest
  @MethodSource("getParams")
  public void testInteropRoundTrips(TestParams params) throws Exception {
    Signature signer = Signature.getInstance("ML-DSA", params.signerProv);
    Signature verifier = Signature.getInstance("ML-DSA", params.verifierProv);
    PrivateKey priv = params.priv;
    PublicKey pub = params.pub;
    byte[] signMessage = params.signMessage;
    byte[] verifyMessage = params.verifyMessage;

    signer.initSign(priv);
    signer.update(signMessage);
    byte[] signatureBytes = signer.sign();

    verifier.initVerify(pub);
    verifier.update(verifyMessage);
    if (Arrays.equals(signMessage, verifyMessage)) {
      assertTrue(verifier.verify(signatureBytes));
    } else {
      assertFalse(verifier.verify(signatureBytes));
    }

    // Because ML-DSA uses per-signature randomness, signatures over identical inputs should be
    // unique
    if (signer.getProvider() == NATIVE_PROVIDER) {
      signer.initSign(priv);
      signer.update(signMessage);
      byte[] secondSignatureBytes = signer.sign();
      assertFalse(Arrays.equals(signatureBytes, secondSignatureBytes));
    }
  }

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
  public void testKeyFactorySelfConversion() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ML-DSA", NATIVE_PROVIDER);
    KeyPair originalKeyPair = keyGen.generateKeyPair();

    KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", NATIVE_PROVIDER);

    byte[] publicKeyEncoded = originalKeyPair.getPublic().getEncoded();
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
    assertArrayEquals(publicKeyEncoded, publicKey.getEncoded());

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

  @Test
  public void codifyBcDifferences() {
    // TODO [childw] hard-coded test to document de/serialization tests between ACCP and BC
  }
}
