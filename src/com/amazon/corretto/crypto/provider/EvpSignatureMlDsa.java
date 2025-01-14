// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

class EvpSignatureMlDsa extends EvpSignatureBase {
  public static final class Level2 extends EvpSignatureMlDsa {
    public Level2(AmazonCorrettoCryptoProvider provider) {
      super(provider, 2);
    }
  }

  public static final class Level3 extends EvpSignatureMlDsa {
    public Level3(AmazonCorrettoCryptoProvider provider) {
      super(provider, 3);
    }
  }

  public static final class Level5 extends EvpSignatureMlDsa {
    public Level5(AmazonCorrettoCryptoProvider provider) {
      super(provider, 5);
    }
  }

  private final int level;
  private final AccessibleByteArrayOutputStream buffer =
      new AccessibleByteArrayOutputStream(64, 1024 * 1024);

  protected EvpSignatureMlDsa(AmazonCorrettoCryptoProvider provider, int level) {
    super(provider, EvpKeyType.MlDsa, 0, 0);
    this.level = level;
  }

  static {
    Loader.checkNativeLibraryAvailability();
  }

  @Override
  protected boolean isBufferEmpty() {
    return buffer.size() == 0;
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof MLDSAPublicKey)) {
      throw new InvalidKeyException("Key must be an instance of MLDSAPublicKey");
    }
    super.engineInitVerify(publicKey);
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (!(privateKey instanceof MLDSAPrivateKey)) {
      throw new InvalidKeyException("Key must be an instance of MLDSAPrivateKey");
    }
    super.engineInitSign(privateKey);
  }

  @Override
  protected void engineReset() {
    buffer.reset();
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    buffer.write(b & 0xFF);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    buffer.write(b, off, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    try {
      ensureInitialized(true);
      return key_.use(
          ptr -> signRaw(ptr, paddingType_, 0, 0, buffer.getDataBuffer(), 0, buffer.size()));
    } finally {
      engineReset();
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    return engineVerify(sigBytes, 0, sigBytes.length);
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes, int offset, int length)
      throws SignatureException {
    try {
      ensureInitialized(false);
      sniffTest(sigBytes, offset, length);
      return key_.use(
          ptr ->
              verifyRaw(
                  ptr,
                  paddingType_,
                  0,
                  0,
                  buffer.getDataBuffer(),
                  0,
                  buffer.size(),
                  sigBytes,
                  offset,
                  length));
    } finally {
      engineReset();
    }
  }

  private static native byte[] signRaw(
      long privateKey,
      int paddingType,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length);

  private static native boolean verifyRaw(
      long publicKey,
      int paddingType,
      long mgfMd,
      int saltLen,
      byte[] message,
      int offset,
      int length,
      byte[] signature,
      int sigOffset,
      int sigLength)
      throws SignatureException;
}
