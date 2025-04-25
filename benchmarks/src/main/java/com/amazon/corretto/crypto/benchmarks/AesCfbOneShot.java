// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.benchmarks;

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

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 3, time = 10, timeUnit = TimeUnit.SECONDS)
@Fork(value = 1, jvmArgsAppend = {"-XX:+AlwaysPreTouch", "-Xms4g", "-Xmx4g"})
@State(Scope.Benchmark)
public class AesCfbOneShot {
  private static final SecureRandom RND = new SecureRandom();

  @Param({"128", "256"})
  private int keySize;

  @Param({"1024", "4096", "16384", "65536"})
  private int dataSize;

  @Param({"SunJCE", "AmazonCorrettoCryptoProvider"})
  private String provider;

  private byte[] key;
  private byte[] iv;
  private byte[] plaintext;
  private byte[] ciphertext;
  private Cipher encryptCipher;
  private Cipher decryptCipher;

  @Setup(Level.Trial)
  public void setupTrial() throws Exception {
    key = new byte[keySize / 8];
    iv = new byte[16]; // AES block size
    plaintext = new byte[dataSize];
    RND.nextBytes(key);
    RND.nextBytes(iv);
    RND.nextBytes(plaintext);

    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);

    encryptCipher = Cipher.getInstance("AES/CFB/NoPadding", provider);
    encryptCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
    ciphertext = encryptCipher.doFinal(plaintext);

    decryptCipher = Cipher.getInstance("AES/CFB/NoPadding", provider);
    decryptCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
  }

  @Benchmark
  public byte[] encrypt() throws Exception {
    return encryptCipher.doFinal(plaintext);
  }

  @Benchmark
  public byte[] decrypt() throws Exception {
    return decryptCipher.doFinal(ciphertext);
  }
}
