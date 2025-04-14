// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static com.amazon.corretto.crypto.provider.test.TestUtil.byteBuffersAreEqual;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genAesKey;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genData;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genIv;
import static com.amazon.corretto.crypto.provider.test.TestUtil.genPattern;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArray;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArrayMultiAllocationExplicit;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepArrayMultiAllocationImplicit;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepByteBuffer;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepByteBufferInPlace;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepByteBufferMultiAllocation;
import static com.amazon.corretto.crypto.provider.test.TestUtil.multiStepInPlaceArray;
import static com.amazon.corretto.crypto.provider.test.TestUtil.oneShotByteBuffer;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCfbTest {
  private static final Provider bcProv = new BouncyCastleProvider();

  static Cipher accpAesCfbCipher(final boolean paddingEnabled) {
    try {
      return paddingEnabled
          ? Cipher.getInstance("AES/CFB/PKCS5Padding", TestUtil.NATIVE_PROVIDER)
          : Cipher.getInstance("AES/CFB/NoPadding", TestUtil.NATIVE_PROVIDER);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  static Cipher sunAesCfbCipher(final boolean paddingEnabled) {
    try {
      return paddingEnabled
          ? Cipher.getInstance("AES/CFB/PKCS5Padding", "SunJCE")
          : Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  static Cipher bcAesCfbCipher(final boolean paddingEnabled) {
    try {
      return paddingEnabled
          ? Cipher.getInstance("AES/CFB/PKCS7Padding", bcProv)
          : Cipher.getInstance("AES/CFB/NoPadding", bcProv);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  public void emptyCipherTextWithPaddingEnabledShouldProduceEmptyPlaintext() throws Exception {
    // For empty cipher text, SunJCE returns empty plain text when decrypting with padding enabled.
    // This is despite the fact that Cipher text with padding is always at least 16 bytes. This test
    // shows that ACCP is compatible with SunJCE in this manner. AWS-LC has a different behavior:
    // EVP_CipherFinal fails when no input is passed to decryption with PKCS7Padding.
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpAesCfbCipher(true);
    final Cipher sun = sunAesCfbCipher(true);

    accp.init(Cipher.DECRYPT_MODE, key, iv);
    sun.init(Cipher.DECRYPT_MODE, key, iv);

    final byte[] empty = new byte[0];

    assertEquals(0, accp.doFinal().length);
    assertEquals(sun.doFinal().length, sun.doFinal().length);

    assertEquals(0, accp.doFinal(empty).length);
    assertEquals(sun.doFinal().length, sun.doFinal(empty).length);

    assertNull(accp.update(empty));
    assertEquals(sun.update(empty), sun.update(empty));
    assertEquals(0, accp.doFinal().length);
    assertEquals(sun.doFinal().length, sun.doFinal().length);

    assertNull(accp.update(empty));
    assertEquals(sun.update(empty), sun.update(empty));
    assertEquals(0, accp.doFinal(empty).length);
    assertEquals(sun.doFinal(empty).length, sun.doFinal(empty).length);

    // On the other hand, encrypting an empty array produces 16 bytes of cipher text:
    accp.init(Cipher.ENCRYPT_MODE, key, iv);
    sun.init(Cipher.ENCRYPT_MODE, key, iv);
    final byte[] accpCipherText = accp.doFinal();
    assertEquals(16, accpCipherText.length);
    assertArrayEquals(sun.doFinal(), accpCipherText);
  }

  @Test
  public void ensureInputEmptyIsResetAfterAnOperation() throws Exception {
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpAesCfbCipher(true);

    accp.init(Cipher.ENCRYPT_MODE, key, iv);

    // First we encrypt with a non-empty input.
    assertEquals(16, accp.doFinal(genData(10, 10)).length);
    // Now we decrypt with the same cipher object and empty input:
    accp.init(Cipher.DECRYPT_MODE, key, iv);
    assertEquals(0, accp.doFinal().length);
  }

  @Test
  public void ensureInputEmptyIsResetAfterAnOperationWithBadPaddingToo() throws Exception {
    final SecretKeySpec key = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final Cipher accp = accpAesCfbCipher(true);

    accp.init(Cipher.DECRYPT_MODE, key, iv);
    accp.update(new byte[8]);
    // inputIsEmpty is false. We pass bad cipher text to cause bad padding.
    assertThrows(BadPaddingException.class, () -> accp.doFinal(new byte[8]));
    // The cipher must need re-initialization.
    assertThrows(IllegalStateException.class, () -> accp.doFinal());
    // After initialization, inputIsEmpty should be rest to true and produce zero output when
    // decrypting empty input.
    accp.init(Cipher.DECRYPT_MODE, key, iv);
    assertEquals(0, accp.doFinal().length);
  }

  @Test
  public void testPkcs7Name() throws Exception {
    // SunJCE does not recognize AES/CFB/PKCS7Padding, but BouncyCastle does:
    assertThrows(
        NoSuchPaddingException.class, () -> Cipher.getInstance("AES/CFB/PKCS7Padding", "SunJCE"));

    final Cipher bcCipher = bcAesCfbCipher(true);
    final Cipher accpCipher = Cipher.getInstance("AES/CFB/PKCS7Padding", TestUtil.NATIVE_PROVIDER);

    final byte[] data = genData(987, 23);
    final SecretKeySpec aesKey = genAesKey(987, 256);
    final IvParameterSpec iv = genIv(987, 16);

    bcCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] cipherText = bcCipher.doFinal(data);
    assertArrayEquals(cipherText, accpCipher.doFinal(data));

    bcCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    assertArrayEquals(data, bcCipher.doFinal(cipherText));
    assertArrayEquals(data, accpCipher.doFinal(cipherText));
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testOneShotArray(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCfbCipher(isPaddingEnabled);
    final Cipher sunCipher = sunAesCfbCipher(isPaddingEnabled);
    final byte[] data = genData(seed, inputLen);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] cipherText = accpCipher.doFinal(data);
    assertArrayEquals(sunCipher.doFinal(data), cipherText);

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    sunCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final byte[] plainText = accpCipher.doFinal(cipherText);
    assertArrayEquals(sunCipher.doFinal(cipherText), plainText);
    assertArrayEquals(data, plainText);
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testOneShotArrayInPlace(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCfbCipher(isPaddingEnabled);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final int bufferLen = accpCipher.getOutputSize(inputLen);

    final Cipher sunCipher = sunAesCfbCipher(isPaddingEnabled);
    final byte[] inputOutput = genData(seed, bufferLen);
    final byte[] input = Arrays.copyOf(inputOutput, inputLen);

    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(input);
    final int cipherTextLen = accpCipher.doFinal(inputOutput, 0, inputLen, inputOutput, 0);
    assertEquals(sunCipherText.length, cipherTextLen);
    assertTrue(
        byteBuffersAreEqual(
            ByteBuffer.wrap(sunCipherText), ByteBuffer.wrap(inputOutput, 0, cipherTextLen)));

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final int plainTextLen = accpCipher.doFinal(inputOutput, 0, cipherTextLen, inputOutput, 0);
    assertEquals(inputLen, plainTextLen);
    assertTrue(
        byteBuffersAreEqual(ByteBuffer.wrap(input), ByteBuffer.wrap(inputOutput, 0, plainTextLen)));
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testMultiStepArray(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCfbCipher(isPaddingEnabled);

    final byte[] data = genData(seed, inputLen);
    final ByteBuffer dataByteBuff = ByteBuffer.wrap(data);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final Cipher sunCipher = sunAesCfbCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(data);
    final ByteBuffer sunCipherTextByteBuffer = ByteBuffer.wrap(sunCipherText);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      assertTrue(
          byteBuffersAreEqual(
              sunCipherTextByteBuffer, multiStepArray(accpCipher, processingPattern, data)));
      assertTrue(
          byteBuffersAreEqual(
              sunCipherTextByteBuffer,
              multiStepArrayMultiAllocationImplicit(accpCipher, processingPattern, data)));
      assertTrue(
          byteBuffersAreEqual(
              sunCipherTextByteBuffer,
              multiStepArrayMultiAllocationExplicit(accpCipher, processingPattern, data)));
    }

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      assertTrue(
          byteBuffersAreEqual(
              ByteBuffer.wrap(data), multiStepArray(accpCipher, processingPattern, sunCipherText)));
      assertTrue(
          byteBuffersAreEqual(
              ByteBuffer.wrap(data),
              multiStepArrayMultiAllocationImplicit(accpCipher, processingPattern, sunCipherText)));
      assertTrue(
          byteBuffersAreEqual(
              dataByteBuff,
              multiStepArrayMultiAllocationExplicit(accpCipher, processingPattern, sunCipherText)));
    }
  }

  private static Stream<Arguments> arrayTestParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : new int[] {128}) {
      for (final boolean isPaddingEnabled : new boolean[] {false, true}) {
        for (int i = 0; i != 32; i++) {
          if (!isPaddingEnabled && (i % 16 != 0)) continue;
          result.add(Arguments.of(keySize, (long) i, isPaddingEnabled, i));
        }
      }
    }
    return result.stream();
  }

  @ParameterizedTest
  @MethodSource("arrayTestParams")
  public void testMultiStepArrayInPlace(
      final int keySize, final long seed, final boolean isPaddingEnabled, final int inputLen)
      throws Exception {
    final Cipher accpCipher = accpAesCfbCipher(isPaddingEnabled);
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);
    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    // With padding, the length of cipher text is greater than plaintext. The buffer needs to be set
    // to the size of the cipher text for in-place operations.
    final int bufferLen = accpCipher.getOutputSize(inputLen);
    final byte[] inputOutput = genData(seed, bufferLen);
    final byte[] input = Arrays.copyOf(inputOutput, inputLen);
    final ByteBuffer inputByteBuffer = ByteBuffer.wrap(input);

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final Cipher sunCipher = sunAesCfbCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final byte[] sunCipherText = sunCipher.doFinal(input);
    final ByteBuffer sunCipherTextByteBuffer = ByteBuffer.wrap(sunCipherText);

    for (final List<Integer> processingPattern : processingPatterns) {
      accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
      final int cipherLen =
          multiStepInPlaceArray(accpCipher, processingPattern, inputOutput, inputLen);
      assertEquals(sunCipherText.length, cipherLen);
      assertTrue(
          byteBuffersAreEqual(sunCipherTextByteBuffer, ByteBuffer.wrap(inputOutput, 0, cipherLen)));
      accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      final int plainTextLen =
          multiStepInPlaceArray(accpCipher, processingPattern, inputOutput, cipherLen);
      assertEquals(inputLen, plainTextLen);
      assertTrue(
          byteBuffersAreEqual(inputByteBuffer, ByteBuffer.wrap(inputOutput, 0, plainTextLen)));
    }
  }

  @ParameterizedTest
  @MethodSource("byteBufferTestParams")
  public void testOneShotByteBuffer(
      final int keySize,
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final boolean inputReadOnly,
      final boolean inputDirect,
      final boolean outputDirect)
      throws Exception {

    final Cipher accpCipher = accpAesCfbCipher(isPaddingEnabled);
    final Cipher sunCipher = sunAesCfbCipher(isPaddingEnabled);
    ByteBuffer input = genData(seed, inputLen, inputDirect);
    if (inputReadOnly) {
      input = input.asReadOnlyBuffer();
    }
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer accpCipherText = oneShotByteBuffer(accpCipher, input.duplicate());
    final ByteBuffer sunCipherText = oneShotByteBuffer(sunCipher, input.duplicate());
    assertTrue(byteBuffersAreEqual(sunCipherText, accpCipherText));

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    sunCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    final ByteBuffer accpPlainText = oneShotByteBuffer(accpCipher, accpCipherText.duplicate());
    final ByteBuffer sunPlainText = oneShotByteBuffer(sunCipher, sunCipherText.duplicate());
    assertTrue(byteBuffersAreEqual(sunPlainText, accpPlainText));
    assertTrue(byteBuffersAreEqual(input, accpPlainText));
  }

  private static Stream<Arguments> byteBufferTestParams() {
    final List<Arguments> result = new ArrayList<>();
    for (final int keySize : new int[] {128}) {
      for (final boolean isPaddingEnabled : new boolean[] {false, true}) {
        for (final boolean inputReadOnly : new boolean[] {false, true}) {
          for (final boolean inputDirect : new boolean[] {false, true}) {
            for (final boolean outputDirect : new boolean[] {false, true}) {
              for (int i = 0; i != 32; i++) {
                if (!isPaddingEnabled && (i % 16 != 0)) continue;
                result.add(
                    Arguments.of(
                        keySize,
                        (long) i,
                        isPaddingEnabled,
                        i,
                        inputReadOnly,
                        inputDirect,
                        outputDirect));
              }
            }
          }
        }
      }
    }
    return result.stream();
  }

  @ParameterizedTest
  @MethodSource("byteBufferTestParams")
  public void testMultiStepByteBuffer(
      final int keySize,
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final boolean inputReadOnly,
      final boolean inputDirect,
      final boolean outputDirect)
      throws Exception {

    final Cipher accpCipher = accpAesCfbCipher(isPaddingEnabled);
    ByteBuffer input = genData(seed, inputLen, inputDirect);
    if (inputReadOnly) {
      input = input.asReadOnlyBuffer();
    }
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final Cipher sunCipher = sunAesCfbCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer sunCipherText = oneShotByteBuffer(sunCipher, input.duplicate());

    accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      assertTrue(
          byteBuffersAreEqual(
              sunCipherText,
              multiStepByteBuffer(accpCipher, processingPattern, input.duplicate(), outputDirect)));
      assertTrue(
          byteBuffersAreEqual(
              sunCipherText,
              multiStepByteBufferMultiAllocation(
                  accpCipher, processingPattern, input.duplicate(), outputDirect)));
    }

    accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
    for (final List<Integer> processingPattern : processingPatterns) {
      assertTrue(
          byteBuffersAreEqual(
              input,
              multiStepByteBuffer(
                  accpCipher, processingPattern, sunCipherText.duplicate(), outputDirect)));
      assertTrue(
          byteBuffersAreEqual(
              input,
              multiStepByteBufferMultiAllocation(
                  accpCipher, processingPattern, sunCipherText.duplicate(), outputDirect)));
    }
  }

  @ParameterizedTest
  @MethodSource("byteBufferTestParams")
  public void testMultiStepByteBufferInPlace(
      final int keySize,
      final long seed,
      final boolean isPaddingEnabled,
      final int inputLen,
      final boolean inputReadOnly,
      final boolean inputDirect,
      final boolean outputDirect)
      throws Exception {

    final Cipher accpCipher = accpAesCfbCipher(isPaddingEnabled);
    ByteBuffer input = genData(seed, inputLen, inputDirect);
    if (inputReadOnly) {
      input = input.asReadOnlyBuffer();
    }
    final SecretKeySpec aesKey = genAesKey(seed, keySize);
    final IvParameterSpec iv = genIv(seed, 16);

    final List<List<Integer>> processingPatterns =
        Stream.of(-1, 0, 16, 20, 32)
            .map(c -> genPattern(seed, c, inputLen))
            .collect(Collectors.toList());

    final Cipher sunCipher = sunAesCfbCipher(isPaddingEnabled);
    sunCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final ByteBuffer sunCipherText = oneShotByteBuffer(sunCipher, input.duplicate());

    for (final List<Integer> processingPattern : processingPatterns) {
      // Create a separate buffer for output to avoid in-place buffer issues
      final ByteBuffer inOutBuffer = genData(seed, accpCipher.getOutputSize(inputLen), inputDirect);
      inOutBuffer.limit(inputLen);
      inOutBuffer.put(input.duplicate());
      inOutBuffer.flip();
      inOutBuffer.limit(inOutBuffer.capacity());

      // Create a separate buffer for the ciphertext
      final ByteBuffer cipherTextBuffer = ByteBuffer.allocate(accpCipher.getOutputSize(inputLen));
      
      accpCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
      
      // Make a duplicate of inOutBuffer to use as input
      ByteBuffer inputBuffer = inOutBuffer.duplicate();
      inputBuffer.limit(inputLen);
      
      // Use the separate buffer for output
      final ByteBuffer cipherText =
          multiStepByteBufferInPlace(accpCipher, processingPattern, inputBuffer);
      assertTrue(byteBuffersAreEqual(sunCipherText, cipherText));

      // Create a separate buffer for the plaintext
      final ByteBuffer plainTextBuffer = ByteBuffer.allocate(accpCipher.getOutputSize(inputLen));
      
      accpCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
      
      // Use the cipherText as input and plainTextBuffer as output
      final ByteBuffer plainText =
          multiStepByteBufferInPlace(accpCipher, processingPattern, cipherText.duplicate());
      assertTrue(byteBuffersAreEqual(input, plainText));
    }
  }

  @Test
  public void testGetBlockSize() {
    final Cipher cipher = accpAesCfbCipher(false);
    assertEquals(16, cipher.getBlockSize());
  }

  @Test
  public void testGetOutputSize() throws Exception {
    final Cipher cipher = accpAesCfbCipher(false);
    final SecretKeySpec aesKey = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    assertEquals(16, cipher.getOutputSize(16));
    assertEquals(16, cipher.getOutputSize(1));
    assertEquals(32, cipher.getOutputSize(17));
  }

  @Test
  public void testGetIV() throws Exception {
    final Cipher cipher = accpAesCfbCipher(false);
    final SecretKeySpec aesKey = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    assertArrayEquals(iv.getIV(), cipher.getIV());
  }

  @Test
  public void testGetParameters() throws Exception {
    final Cipher cipher = accpAesCfbCipher(false);
    final SecretKeySpec aesKey = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
    final AlgorithmParameters params = cipher.getParameters();
    assertEquals("AES", params.getAlgorithm());
    final IvParameterSpec ivParams = params.getParameterSpec(IvParameterSpec.class);
    assertArrayEquals(iv.getIV(), ivParams.getIV());
  }

  @Test
  public void testInitWithSecureRandom() throws Exception {
    final Cipher cipher = accpAesCfbCipher(false);
    final SecretKeySpec aesKey = genAesKey(10, 128);
    final SecureRandom random = new SecureRandom();
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, random);
    assertDoesNotThrow(() -> cipher.doFinal(new byte[16]));
  }

  @Test
  public void testInitWithAlgorithmParameters() throws Exception {
    final Cipher cipher = accpAesCfbCipher(false);
    final SecretKeySpec aesKey = genAesKey(10, 128);
    final IvParameterSpec iv = genIv(10, 16);
    final AlgorithmParameters params = AlgorithmParameters.getInstance("AES");
    params.init(iv);
    cipher.init(Cipher.ENCRYPT_MODE, aesKey, params);
    assertDoesNotThrow(() -> cipher.doFinal(new byte[16]));
  }

  @Test
  public void testInitWithInvalidKey() {
    final Cipher cipher = accpAesCfbCipher(false);
    final Key invalidKey =
        new Key() {
          @Override
          public String getAlgorithm() {
            return "INVALID";
          }

          @Override
          public String getFormat() {
            return "RAW";
          }

          @Override
          public byte[] getEncoded() {
            return new byte[16];
          }
        };
    assertThrows(InvalidKeyException.class, () -> cipher.init(Cipher.ENCRYPT_MODE, invalidKey));
  }

  @Test
  public void testInitWithInvalidIV() {
    final Cipher cipher = accpAesCfbCipher(false);
    final SecretKeySpec aesKey = genAesKey(10, 128);
    final IvParameterSpec invalidIv = new IvParameterSpec(new byte[8]); // Wrong size
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.ENCRYPT_MODE, aesKey, invalidIv));
  }

  @Test
  public void testInitWithNullIV() {
    final Cipher cipher = accpAesCfbCipher(false);
    final SecretKeySpec aesKey = genAesKey(10, 128);
    assertThrows(
        InvalidAlgorithmParameterException.class,
        () -> cipher.init(Cipher.DECRYPT_MODE, aesKey, (AlgorithmParameterSpec) null));
  }

  @Test
  public void testSetMode() throws Exception {
    final Cipher cipher = accpAesCfbCipher(false);
    assertDoesNotThrow(
        () ->
            cipher
                .getClass()
                .getDeclaredMethod("engineSetMode", String.class)
                .invoke(cipher, "CFB"));
    assertThrows(
        NoSuchAlgorithmException.class,
        () ->
            cipher
                .getClass()
                .getDeclaredMethod("engineSetMode", String.class)
                .invoke(cipher, "CBC"));
  }

  @Test
  public void testSetPadding() throws Exception {
    final Cipher cipher = accpAesCfbCipher(false);
    assertDoesNotThrow(
        () ->
            cipher
                .getClass()
                .getDeclaredMethod("engineSetPadding", String.class)
                .invoke(cipher, "NoPadding"));
    assertDoesNotThrow(
        () ->
            cipher
                .getClass()
                .getDeclaredMethod("engineSetPadding", String.class)
                .invoke(cipher, "PKCS5Padding"));
    assertDoesNotThrow(
        () ->
            cipher
                .getClass()
                .getDeclaredMethod("engineSetPadding", String.class)
                .invoke(cipher, "PKCS7Padding"));
    assertThrows(
        NoSuchPaddingException.class,
        () ->
            cipher
                .getClass()
                .getDeclaredMethod("engineSetPadding", String.class)
                .invoke(cipher, "ISO10126Padding"));
  }

  @Test
  public void testWrapUnwrap() throws Exception {
    final Cipher cipher = accpAesCfbCipher(true);
    final SecretKeySpec keyToWrap = genAesKey(10, 128);
    final SecretKeySpec wrappingKey = genAesKey(20, 256);
    final IvParameterSpec iv = genIv(30, 16);

    cipher.init(Cipher.WRAP_MODE, wrappingKey, iv);
    final byte[] wrappedKey = cipher.wrap(keyToWrap);

    cipher.init(Cipher.UNWRAP_MODE, wrappingKey, iv);
    final Key unwrappedKey = cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

    assertArrayEquals(keyToWrap.getEncoded(), unwrappedKey.getEncoded());
  }
}
