// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

final class MLDSASignature extends SignatureSpi {
  private final long ctx;
  private State state = State.UNINITIALIZED;
  private byte[] precomputedHash;
  private String algorithmName;

  private enum State {
    UNINITIALIZED,
    SIGN,
    VERIFY
  }

  MLDSASignature() {
    ctx = nativeCreateContext();
    if (ctx == 0) {
      throw new ProviderException("Unable to create context");
    }
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    if (!(publicKey instanceof MLDSAPublicKey)) {
      throw new InvalidKeyException("Key must be an instance of MLDSAPublicKey");
    }
    MLDSAPublicKey key = (MLDSAPublicKey) publicKey;

    if (!nativeInitVerify(ctx, key.getEncoded(), key.getLevel())) {
      throw new InvalidKeyException("Failed to initialize verification");
    }
    state = State.VERIFY;
    precomputedHash = null;
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    engineInitSign(privateKey, null);
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
      throws InvalidKeyException {
    if (!(privateKey instanceof MLDSAPrivateKey)) {
      throw new InvalidKeyException("Key must be an instance of MLDSAPrivateKey");
    }
    MLDSAPrivateKey key = (MLDSAPrivateKey) privateKey;

    if (!nativeInitSign(ctx, key.getEncoded(), key.getLevel())) {
      throw new InvalidKeyException("Failed to initialize signing");
    }
    state = State.SIGN;
    precomputedHash = null;
  }

  @Override
  protected void engineUpdate(byte b) throws SignatureException {
    engineUpdate(new byte[] {b}, 0, 1);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    if (state == State.UNINITIALIZED) {
      throw new SignatureException("ML-DSA signature not initialized");
    }

    if (b == null) {
      throw new SignatureException("Input buffer is null");
    }

    if (off < 0 || len < 0 || len > b.length - off) {
      throw new SignatureException("Invalid buffer offset or length");
    }

    if (!nativeUpdate(ctx, b, off, len)) {
      throw new SignatureException("Failed to update signature");
    }
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (state != State.SIGN) {
      throw new SignatureException("Not initialized for signing");
    }

    byte[] signature = nativeSign(ctx);
    if (signature == null) {
      throw new SignatureException("Failed to generate signature");
    }
    return signature;
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    if (state != State.VERIFY) {
      throw new SignatureException("Not initialized for verification");
    }

    if (sigBytes == null) {
      throw new SignatureException("Signature bytes are null");
    }

    return nativeVerify(ctx, sigBytes);
  }

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    throw new UnsupportedOperationException("ML-DSA does not support parameters");
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void engineSetParameter(String param, Object value) {
    throw new UnsupportedOperationException("ML-DSA does not support parameters");
  }

  @Override
  @SuppressWarnings("deprecation")
  protected Object engineGetParameter(String param) {
    throw new UnsupportedOperationException("ML-DSA does not support parameters");
  }

  @Override
  @SuppressWarnings("deprecation")
  protected void finalize() throws Throwable {
    try {
      if (ctx != 0) {
        nativeDestroyContext(ctx);
      }
    } finally {
      super.finalize();
    }
  }

  private static native long nativeCreateContext();

  private static native void nativeDestroyContext(long ctx);

  private static native boolean nativeInitSign(long ctx, byte[] privateKey, int level);

  private static native boolean nativeInitVerify(long ctx, byte[] publicKey, int level);

  private static native boolean nativeUpdate(long ctx, byte[] data, int offset, int length);

  private static native byte[] nativeSign(long ctx);

  private static native boolean nativeVerify(long ctx, byte[] signature);

  public void setAlgorithmName(String name) {
    this.algorithmName = name;
  }

  static {
    Loader.load();
  }
}
