// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.assertArraysHexEquals;
import static com.amazon.corretto.crypto.provider.test.TestUtil.assertThrows;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCfbTest {
  private static final String PROVIDER_NAME = AmazonCorrettoCryptoProvider.PROVIDER_NAME;
  private static final int BLOCK_SIZE = 16;
  private static final int KEY_SIZE_128 = 128;
  private static final int KEY_SIZE_256 = 256;
  private static final String ALGORITHM = "AES/CFB/NoPadding";
  private static final String ALGORITHM_128 = "AES_128/CFB/NoPadding";
  private static final String ALGORITHM_256 = "AES_256/CFB/NoPadding";
  private static final SecureRandom RND = new SecureRandom();

  @BeforeAll
  public static void setUp() {
    AmazonCorrettoCryptoProvider.install();
  }

  @Test
  public void testBasicEncryptDecrypt() throws Exception {
    final byte[] plaintext = new byte[1024];
    RND.nextBytes(plaintext);

    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(ciphertext);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testBasicEncryptDecrypt256() throws Exception {
    final byte[] plaintext = new byte[1024];
    RND.nextBytes(plaintext);

    final SecretKey key = generateKey(KEY_SIZE_256);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM_256, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM_256, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(ciphertext);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testEmptyInput() throws Exception {
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(new byte[0]);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(ciphertext);

    assertEquals(0, decrypted.length);
  }

  @Test
  public void testMultiPartEncryption() throws Exception {
    final byte[] plaintext = new byte[1024];
    RND.nextBytes(plaintext);

    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(encryptCipher.update(plaintext, 0, 100));
    baos.write(encryptCipher.update(plaintext, 100, 400));
    baos.write(encryptCipher.update(plaintext, 500, 524));
    baos.write(encryptCipher.doFinal());
    final byte[] ciphertext = baos.toByteArray();

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(ciphertext);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testMultiPartDecryption() throws Exception {
    final byte[] plaintext = new byte[1024];
    RND.nextBytes(plaintext);

    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(decryptCipher.update(ciphertext, 0, 100));
    baos.write(decryptCipher.update(ciphertext, 100, 400));
    baos.write(decryptCipher.update(ciphertext, 500, ciphertext.length - 500));
    baos.write(decryptCipher.doFinal());
    final byte[] decrypted = baos.toByteArray();

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testByteBufferEncryptDecrypt() throws Exception {
    final byte[] plaintext = new byte[1024];
    RND.nextBytes(plaintext);

    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    final ByteBuffer plaintextBuf = ByteBuffer.wrap(plaintext);
    final ByteBuffer ciphertextBuf =
        ByteBuffer.allocate(encryptCipher.getOutputSize(plaintext.length));
    encryptCipher.doFinal(plaintextBuf, ciphertextBuf);
    ciphertextBuf.flip();

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    final ByteBuffer decryptedBuf =
        ByteBuffer.allocate(decryptCipher.getOutputSize(ciphertextBuf.remaining()));
    decryptCipher.doFinal(ciphertextBuf, decryptedBuf);
    decryptedBuf.flip();

    final byte[] decrypted = new byte[decryptedBuf.remaining()];
    decryptedBuf.get(decrypted);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testDirectByteBufferEncryptDecrypt() throws Exception {
    final byte[] plaintext = new byte[1024];
    RND.nextBytes(plaintext);

    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    final ByteBuffer plaintextBuf = ByteBuffer.allocateDirect(plaintext.length);
    plaintextBuf.put(plaintext);
    plaintextBuf.flip();

    final ByteBuffer ciphertextBuf =
        ByteBuffer.allocateDirect(encryptCipher.getOutputSize(plaintext.length));
    encryptCipher.doFinal(plaintextBuf, ciphertextBuf);
    ciphertextBuf.flip();

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

    final ByteBuffer decryptedBuf =
        ByteBuffer.allocateDirect(decryptCipher.getOutputSize(ciphertextBuf.remaining()));
    decryptCipher.doFinal(ciphertextBuf, decryptedBuf);
    decryptedBuf.flip();

    final byte[] decrypted = new byte[decryptedBuf.remaining()];
    decryptedBuf.get(decrypted);

    assertArrayEquals(plaintext, decrypted);
  }

  @Test
  public void testInvalidKeySize() throws Exception {
    final byte[] invalidKey = new byte[24]; // 192 bits, not supported
    RND.nextBytes(invalidKey);
    final SecretKeySpec keySpec = new SecretKeySpec(invalidKey, "AES");

    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);

    try {
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
      fail("Expected InvalidKeyException");
    } catch (InvalidKeyException e) {
      // Expected
    }
  }

  @Test
  public void testInvalidIvSize() throws Exception {
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] invalidIv = new byte[8]; // Too short
    RND.nextBytes(invalidIv);
    final IvParameterSpec ivSpec = new IvParameterSpec(invalidIv);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);

    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec));
  }

  @Test
  public void testInvalidMode() throws Exception {
    assertThrows(
        NoSuchAlgorithmException.class,
        () -> Cipher.getInstance("AES/ECB/NoPadding", PROVIDER_NAME));
  }

  @Test
  public void testInvalidPadding() throws Exception {
    try {
      Cipher.getInstance("AES/CFB/PKCS5Padding", PROVIDER_NAME);
      fail("Expected NoSuchPaddingException");
    } catch (NoSuchPaddingException e) {
      // Expected
    }
  }

  @Test
  public void testGetBlockSize() throws Exception {
    final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    assertEquals(BLOCK_SIZE, cipher.getBlockSize());
  }

  @Test
  public void testGetIV() throws Exception {
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    assertArrayEquals(iv, cipher.getIV());
  }

  @Test
  public void testGetParameters() throws Exception {
    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher cipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

    final AlgorithmParameters params = cipher.getParameters();
    assertNotNull(params);
    assertEquals("AES", params.getAlgorithm());

    final IvParameterSpec retrievedIvSpec = params.getParameterSpec(IvParameterSpec.class);
    assertArrayEquals(iv, retrievedIvSpec.getIV());
  }

  @Test
  public void testWrapUnwrap() throws Exception {
    final SecretKey keyToWrap = generateKey(KEY_SIZE_128);
    final SecretKey wrappingKey = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher wrapCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    wrapCipher.init(Cipher.WRAP_MODE, wrappingKey, ivSpec);
    final byte[] wrapped = wrapCipher.wrap(keyToWrap);

    final Cipher unwrapCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    unwrapCipher.init(Cipher.UNWRAP_MODE, wrappingKey, ivSpec);
    final java.security.Key unwrapped = unwrapCipher.unwrap(wrapped, "AES", Cipher.SECRET_KEY);

    assertArrayEquals(keyToWrap.getEncoded(), unwrapped.getEncoded());
  }

  @Test
  public void testCompatibilityWithSunJCE() throws Exception {
    // Skip if SunJCE provider is not available
    try {
      Cipher.getInstance(ALGORITHM, "SunJCE");
    } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
      return; // Skip test
    }

    final byte[] plaintext = new byte[1024];
    RND.nextBytes(plaintext);

    final SecretKey key = generateKey(KEY_SIZE_128);
    final byte[] iv = new byte[BLOCK_SIZE];
    RND.nextBytes(iv);
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // Encrypt with SunJCE
    final Cipher sunEncryptCipher = Cipher.getInstance(ALGORITHM, "SunJCE");
    sunEncryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] sunCiphertext = sunEncryptCipher.doFinal(plaintext);

    // Decrypt with ACCP
    final Cipher accpDecryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    accpDecryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] accpDecrypted = accpDecryptCipher.doFinal(sunCiphertext);

    assertArrayEquals(plaintext, accpDecrypted);

    // Encrypt with ACCP
    final Cipher accpEncryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    accpEncryptCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
    final byte[] accpCiphertext = accpEncryptCipher.doFinal(plaintext);

    // Decrypt with SunJCE
    final Cipher sunDecryptCipher = Cipher.getInstance(ALGORITHM, "SunJCE");
    sunDecryptCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
    final byte[] sunDecrypted = sunDecryptCipher.doFinal(accpCiphertext);

    assertArrayEquals(plaintext, sunDecrypted);
  }

  // NIST SP 800-38A CFB128 test vectors
  @Test
  public void testNistKAT() throws Exception {
    // Test vector from NIST SP 800-38A, F.3.13 CFB128-AES128.Encrypt
    final byte[] key = TestUtil.decodeHex("2b7e151628aed2a6abf7158809cf4f3c");
    final byte[] iv = TestUtil.decodeHex("000102030405060708090a0b0c0d0e0f");
    final byte[] plaintext =
        TestUtil.decodeHex(
            "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411e5fbc1191a0a52ef"
                + "f69f2445df4f9b17ad2b417be66c3710");
    final byte[] expectedCiphertext =
        TestUtil.decodeHex(
            "3b3fd92eb72dad20333449f8e83cfb4a"
                + "c8a64537a0b3a93fcde3cdad9f1ce58b"
                + "26751f67a3cbb140b1808cf187a4f4df"
                + "c04b05357c5d1c0eeac4c66f9ff7f2e6");

    final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);

    assertArraysHexEquals(expectedCiphertext, ciphertext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(ciphertext);

    assertArraysHexEquals(plaintext, decrypted);
  }

  @Test
  public void testNistKAT256() throws Exception {
    // Test vector from NIST SP 800-38A, F.3.15 CFB128-AES256.Encrypt
    final byte[] key =
        TestUtil.decodeHex("603deb1015ca71be2b73aef0857d7781" + "1f352c073b6108d72d9810a30914dff4");
    final byte[] iv = TestUtil.decodeHex("000102030405060708090a0b0c0d0e0f");
    final byte[] plaintext =
        TestUtil.decodeHex(
            "6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411e5fbc1191a0a52ef"
                + "f69f2445df4f9b17ad2b417be66c3710");
    final byte[] expectedCiphertext =
        TestUtil.decodeHex(
            "dc7e84bfda79164b7ecd8486985d3860"
                + "39ffed143b28b1c832113c6331e5407b"
                + "df10132415e54b92a13ed0a8267ae2f9"
                + "75a385741ab9cef82031623d55b1e471");

    final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    final Cipher encryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    final byte[] ciphertext = encryptCipher.doFinal(plaintext);

    assertArraysHexEquals(expectedCiphertext, ciphertext);

    final Cipher decryptCipher = Cipher.getInstance(ALGORITHM, PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    final byte[] decrypted = decryptCipher.doFinal(ciphertext);

    assertArraysHexEquals(plaintext, decrypted);
  }

  private SecretKey generateKey(int keySize)
      throws NoSuchAlgorithmException, NoSuchProviderException {
    final KeyGenerator keyGen = KeyGenerator.getInstance("AES", PROVIDER_NAME);
    keyGen.init(keySize);
    return keyGen.generateKey();
  }
}
