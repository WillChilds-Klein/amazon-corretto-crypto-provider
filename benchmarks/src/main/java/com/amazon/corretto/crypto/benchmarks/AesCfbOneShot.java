// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.benchmarks;

import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 5)
@Measurement(iterations = 5, time = 5)
@Fork(value = 1)
@State(Scope.Benchmark)
public class AesCfbOneShot {
  private static final SecureRandom RND = new SecureRandom();

  @Param({"128", "256"})
  private int keySize;

  @Param({"1024", "4096", "16384"})
  private int dataSize;

  private byte[] key;
  private byte[] iv;
  private byte[] plaintext;
  private byte[] ciphertext;
  private SecretKeySpec keySpec;
  private IvParameterSpec ivSpec;
  private Cipher encryptCipher;
  private Cipher decryptCipher;

  @Setup(Level.Trial)
  public void setupTrial() throws Exception {
    AmazonCorrettoCryptoProvider.install();

    key = new byte[keySize / 8];
    iv = new byte[16]; // AES block size
    plaintext = new byte[dataSize];
    RND.nextBytes(key);
    RND.nextBytes(iv);
    RND.nextBytes(plaintext);

    keySpec = new SecretKeySpec(key, "AES");
    ivSpec = new IvParameterSpec(iv);

    encryptCipher = Cipher.getInstance("AES/CFB/NoPadding", AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    ciphertext = encryptCipher.doFinal(plaintext);

    decryptCipher = Cipher.getInstance("AES/CFB/NoPadding", AmazonCorrettoCryptoProvider.PROVIDER_NAME);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
  }

  @Benchmark
  public byte[] encrypt() throws Exception {
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    return encryptCipher.doFinal(plaintext);
  }

  @Benchmark
  public byte[] decrypt() throws Exception {
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
    return decryptCipher.doFinal(ciphertext);
  }
}
