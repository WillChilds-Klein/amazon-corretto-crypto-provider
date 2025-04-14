// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.security.Provider;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class AesCfbKatTest {
  private static final Provider PROVIDER = TestUtil.NATIVE_PROVIDER;

  private static Collection<Object[]> getTestVectors() throws Exception {
    return Arrays.asList(
        new Object[][] {
          // Test vectors from NIST SP 800-38A
          // F.3.13 CFB128-AES128.Encrypt
          {
            "2b7e151628aed2a6abf7158809cf4f3c", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a", // plaintext
            "3b3fd92eb72dad20333449f8e83cfb4a", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "2b7e151628aed2a6abf7158809cf4f3c", // key
            "3b3fd92eb72dad20333449f8e83cfb4a", // iv (previous ciphertext)
            "ae2d8a571e03ac9c9eb76fac45af8e51", // plaintext
            "c8a64537a0b3a93fcde3cdad9f1ce58b", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "2b7e151628aed2a6abf7158809cf4f3c", // key
            "c8a64537a0b3a93fcde3cdad9f1ce58b", // iv (previous ciphertext)
            "30c81c46a35ce411e5fbc1191a0a52ef", // plaintext
            "26751f67a3cbb140b1808cf187a4f4df", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "2b7e151628aed2a6abf7158809cf4f3c", // key
            "26751f67a3cbb140b1808cf187a4f4df", // iv (previous ciphertext)
            "f69f2445df4f9b17ad2b417be66c3710", // plaintext
            "c04b05357c5d1c0eeac4c66f9ff7f2e6", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          // F.3.14 CFB128-AES192.Encrypt
          {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a", // plaintext
            "cdc80d6fddf18cab34c25909c99a4174", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", // key
            "cdc80d6fddf18cab34c25909c99a4174", // iv (previous ciphertext)
            "ae2d8a571e03ac9c9eb76fac45af8e51", // plaintext
            "67ce7f7f81173621961a2b70171d3d7a", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", // key
            "67ce7f7f81173621961a2b70171d3d7a", // iv (previous ciphertext)
            "30c81c46a35ce411e5fbc1191a0a52ef", // plaintext
            "2e1e8a1dd59b88b1c8e60fed1efac4c9", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", // key
            "2e1e8a1dd59b88b1c8e60fed1efac4c9", // iv (previous ciphertext)
            "f69f2445df4f9b17ad2b417be66c3710", // plaintext
            "c05f9f9ca9834fa042ae8fba584b09ff", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          // F.3.15 CFB128-AES256.Encrypt
          {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a", // plaintext
            "dc7e84bfda79164b7ecd8486985d3860", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", // key
            "dc7e84bfda79164b7ecd8486985d3860", // iv (previous ciphertext)
            "ae2d8a571e03ac9c9eb76fac45af8e51", // plaintext
            "39ffed143b28b1c832113c6331e5407b", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", // key
            "39ffed143b28b1c832113c6331e5407b", // iv (previous ciphertext)
            "30c81c46a35ce411e5fbc1191a0a52ef", // plaintext
            "df10132415e54b92a13ed0a8267ae2f9", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", // key
            "df10132415e54b92a13ed0a8267ae2f9", // iv (previous ciphertext)
            "f69f2445df4f9b17ad2b417be66c3710", // plaintext
            "75a385741ab9cef82031623d55b1e471", // ciphertext
            "AES/CFB/NoPadding" // transformation
          },
          // Additional test vectors with PKCS5Padding
          {
            "2b7e151628aed2a6abf7158809cf4f3c", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a", // plaintext
            "3b3fd92eb72dad20333449f8e83cfb4a", // ciphertext
            "AES/CFB/PKCS5Padding" // transformation
          },
          {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a", // plaintext
            "cdc80d6fddf18cab34c25909c99a4174", // ciphertext
            "AES/CFB/PKCS5Padding" // transformation
          },
          {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a", // plaintext
            "dc7e84bfda79164b7ecd8486985d3860", // ciphertext
            "AES/CFB/PKCS5Padding" // transformation
          },
          // Test vectors with non-block-aligned plaintext (requiring padding)
          {
            "2b7e151628aed2a6abf7158809cf4f3c", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a01", // plaintext (17 bytes)
            "3b3fd92eb72dad20333449f8e83cfb4a67", // ciphertext
            "AES/CFB/PKCS5Padding" // transformation
          },
          {
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a0102", // plaintext (18 bytes)
            "cdc80d6fddf18cab34c25909c99a4174c8e1", // ciphertext
            "AES/CFB/PKCS5Padding" // transformation
          },
          {
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", // key
            "000102030405060708090a0b0c0d0e0f", // iv
            "6bc1bee22e409f96e93d7e117393172a010203", // plaintext (19 bytes)
            "dc7e84bfda79164b7ecd8486985d386096d064", // ciphertext
            "AES/CFB/PKCS5Padding" // transformation
          }
        });
  }

  @ParameterizedTest
  @MethodSource("getTestVectors")
  public void testKat(
      final String keyHex,
      final String ivHex,
      final String plaintextHex,
      final String ciphertextHex,
      final String transformation)
      throws Exception {
    final byte[] key = Hex.decodeHex(keyHex.toCharArray());
    final byte[] iv = Hex.decodeHex(ivHex.toCharArray());
    final byte[] plaintext = Hex.decodeHex(plaintextHex.toCharArray());
    final byte[] ciphertext = Hex.decodeHex(ciphertextHex.toCharArray());

    final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    final IvParameterSpec ivSpec = new IvParameterSpec(iv);

    // Test encryption
    final Cipher encryptCipher = Cipher.getInstance(transformation, PROVIDER);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    final byte[] actualCiphertext = encryptCipher.doFinal(plaintext);
    assertArrayEquals(ciphertext, actualCiphertext, "Encryption failed for " + transformation);

    // Test decryption
    final Cipher decryptCipher = Cipher.getInstance(transformation, PROVIDER);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    final byte[] actualPlaintext = decryptCipher.doFinal(ciphertext);
    assertArrayEquals(plaintext, actualPlaintext, "Decryption failed for " + transformation);
  }
}
