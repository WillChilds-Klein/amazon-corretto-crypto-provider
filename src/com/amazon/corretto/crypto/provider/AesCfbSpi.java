// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import static com.amazon.corretto.crypto.provider.Utils.checkAesKey;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

class AesCfbSpi extends CipherSpi {
  public static final Set<String> AES_CFB_NO_PADDING_NAMES;
  public static final Set<String> AES_CFB_PKCS5_PADDING_NAMES;

  static {
    Loader.load();
    AES_CFB_NO_PADDING_NAMES =
        Collections.unmodifiableSet(
            new HashSet<>(
                Arrays.asList(
                    "AES/CFB/NoPadding".toLowerCase(),
                    "AES_128/CFB/NoPadding".toLowerCase(),
                    "AES_256/CFB/NoPadding".toLowerCase())));

    AES_CFB_PKCS5_PADDING_NAMES =
        Collections.unmodifiableSet(
            new HashSet<>(
                Arrays.asList(
                    "AES/CFB/PKCS5Padding".toLowerCase(),
                    "AES_128/CFB/PKCS5Padding".toLowerCase(),
                    "AES_256/CFB/PKCS5Padding".toLowerCase())));
  }

  private static final byte[] EMPTY_ARRAY = new byte[0];
  private static final int BLOCK_SIZE_IN_BYTES = 128 / 8;
  private static final int MODE_NOT_SET = -1;
  // ENC_MODE and DEC_MODE are passed to AWS-LC and respect EVP_CipherInit_ex API:
  // https://github.com/aws/aws-lc/blob/main/include/openssl/cipher.h#L168
  private static final int ENC_MODE = 1;
  private static final int DEC_MODE = 0;

  private enum CipherState {
    NEEDS_INITIALIZATION,
    INITIALIZED,
    UPDATED,
  }

  // State
  private CipherState cipherState;
  private int unprocessedInput;
  private int opMode;
  private byte[] key;
  private byte[] iv;
  // nativeCtx is used to avoid memory leaks in case of multi-step operations or when the
  // EVP_CIPHER_CTX needs to be preserved.
  private NativeEvpCipherCtx nativeCtx;
  // Determines if the EVP_CIPHER_CTX used should be released after doFinal or not. This is
  // controlled by a system property.
  private final boolean saveContext;
  // This flag is initially true. Whenever a non-zero input is passed, it is set to false, and it
  // remains false till the cipher is done processing.
  private boolean inputIsEmpty;

  AesCfbSpi(final boolean saveContext) {
    this.cipherState = CipherState.NEEDS_INITIALIZATION;
    this.unprocessedInput = 0;
    this.opMode = MODE_NOT_SET;
    this.key = null;
    this.iv = null;
    this.nativeCtx = null;
    this.saveContext = saveContext;
    this.inputIsEmpty = true;
  }

  @Override
  protected void engineSetMode(final String mode) throws NoSuchAlgorithmException {
    if (!"CFB".equalsIgnoreCase(mode)) {
      throw new NoSuchAlgorithmException("Only CFB mode is supported.");
    }
  }

  @Override
  protected void engineSetPadding(final String padding) throws NoSuchPaddingException {
    if (padding == null) {
      throw new NoSuchPaddingException("Padding cannot be null.");
    }
    if (!inputIsEmpty) {
      throw new NoSuchPaddingException("Padding cannot be set during an operation.");
    }
    if (!"NoPadding".equalsIgnoreCase(padding)) {
      throw new NoSuchPaddingException(String.format("%s is not a supported padding.", padding));
    }
  }

  @Override
  protected int engineGetBlockSize() {
    return BLOCK_SIZE_IN_BYTES;
  }

  @Override
  protected int engineGetOutputSize(final int inputLen) {
    // There is no need to check if the Cipher is initialized since
    // javax.crypto.Cipher::getOutputSize checks that.

    // This method cannot assume if the next operation is going to be engineUpdate or engineDoFinal.
    // We provide separate methods to find the output length for engineUpdates and engineDoFinals to
    // avoid over allocation and alignment checking of input.
    final long all = inputLen + unprocessedInput;

    // CFB mode doesn't require padding, so the output size is the same as the input size
    return (int) all;
  }

  @Override
  protected byte[] engineGetIV() {
    return iv == null ? null : iv.clone();
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("AES");
      byte[] ivForParams = iv;
      if (ivForParams == null) {
        // We aren't initialized, so we return default and random values
        ivForParams = new byte[BLOCK_SIZE_IN_BYTES];
        new LibCryptoRng().nextBytes(ivForParams);
      }
      parameters.init(new IvParameterSpec(ivForParams));
      return parameters;
    } catch (final InvalidParameterSpecException | NoSuchAlgorithmException e) {
      throw new Error("Unexpected error", e);
    }
  }

  @Override
  protected void engineInit(final int opmode, final Key key, final SecureRandom random)
      throws InvalidKeyException {
    if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.WRAP_MODE) {
      throw new InvalidKeyException("IV required for decrypt");
    }

    final byte[] iv = new byte[BLOCK_SIZE_IN_BYTES];
    random.nextBytes(iv);

    try {
      engineInit(opmode, key, new IvParameterSpec(iv), null);
    } catch (final InvalidAlgorithmParameterException e) {
      throw new RuntimeCryptoException(e);
    }
  }

  @Override
  protected void engineInit(
      final int opmode, final Key key, final AlgorithmParameters params, final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    try {
      engineInit(opmode, key, params.getParameterSpec(IvParameterSpec.class), null);
    } catch (final InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  @Override
  protected void engineInit(
      final int opmode,
      final Key key,
      final AlgorithmParameterSpec params,
      final SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    final int opMode = checkOperation(opmode);
    final byte[] iv = checkAesCfbIv(params);
    final byte[] keyBytes = checkAesKey(key);

    // Check for valid key sizes (only 128 and 256 bits are supported)
    if (keyBytes.length != 16 && keyBytes.length != 32) {
      throw new InvalidKeyException("Invalid AES key size: " + (keyBytes.length * 8) + " bits");
    }

    // All checks passes, so we update the state:
    this.cipherState = CipherState.INITIALIZED;
    this.opMode = opMode;
    this.iv = iv;
    this.key = keyBytes;
    this.unprocessedInput = 0;
    this.inputIsEmpty = true;
  }

  private static int checkOperation(final int opMode) throws InvalidParameterException {
    return ((opMode == Cipher.ENCRYPT_MODE) || (opMode == Cipher.WRAP_MODE)) ? ENC_MODE : DEC_MODE;
  }

  private static byte[] checkAesCfbIv(final AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (!(params instanceof IvParameterSpec)) {
      if (params == null) {
        throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec cannot be null.");
      } else {
        throw new InvalidAlgorithmParameterException(
            "Unknown AlgorithmParameterSpec: " + params.getClass());
      }
    }

    final IvParameterSpec ivParameterSpec = (IvParameterSpec) params;
    final byte[] iv = ivParameterSpec.getIV();
    if (iv.length != BLOCK_SIZE_IN_BYTES) {
      throw new InvalidAlgorithmParameterException("Invalid IV for AES/CFB");
    }

    return iv;
  }

  @Override
  protected byte[] engineUpdate(final byte[] input, final int inputOffset, final int inputLen) {
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    // Since we allocate the output's memory, we only check if the cipher is in the correct state.
    finalOrUpdateStateCheck();
    final byte[] result = new byte[getOutputSizeUpdate(inputLen)];
    final int resultLen = update(null, input, inputOffset, inputLen, null, result, 0);
    return result.length == resultLen ? result : Arrays.copyOf(result, resultLen);
  }

  @Override
  protected int engineUpdate(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException {
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, output.length - outputOffset);
    updateChecks(inputLen, output.length - outputOffset);
    return update(null, input, inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineUpdate(final ByteBuffer input, final ByteBuffer output)
      throws ShortBufferException {
    updateChecks(input.remaining(), output.remaining());

    final ShimByteBuffer inputShimByteBuffer = new ShimByteBuffer(input, true);
    final ShimByteBuffer outputShimByteBuffer = new ShimByteBuffer(output, false);

    final int result =
        update(
            inputShimByteBuffer.directByteBuffer,
            inputShimByteBuffer.array,
            inputShimByteBuffer.offset,
            input.remaining(),
            outputShimByteBuffer.directByteBuffer,
            outputShimByteBuffer.array,
            outputShimByteBuffer.offset);

    outputShimByteBuffer.writeBack(result);

    input.position(input.limit());
    output.position(output.position() + result);

    return result;
  }

  private void finalOrUpdateStateCheck() {
    if (cipherState == CipherState.NEEDS_INITIALIZATION) {
      throw new IllegalStateException("Cipher needs initialization.");
    }
  }

  private void updateChecks(final int inputLen, final int outputLen) throws ShortBufferException {
    finalOrUpdateStateCheck();
    if (outputLen < getOutputSizeUpdate(inputLen)) {
      throw new ShortBufferException();
    }
  }

  private int getOutputSizeUpdate(final int inputLen) {
    return inputLen;
  }

  private int update(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset) {

    if (inputLen > 0) {
      inputIsEmpty = false;
    }

    // Unlike, doFinal (which needs to decide if a context should be released or not), update always
    // has to save the context.

    final long[] ctxContainer = new long[] {0};
    try {
      final int result;
      if (cipherState == CipherState.INITIALIZED) {
        if (nativeCtx != null) {
          result =
              nativeCtx.use(
                  ctxPtr ->
                      nInitUpdate(
                          opMode,
                          key,
                          key.length,
                          iv,
                          null,
                          ctxPtr,
                          inputDirect,
                          inputArray,
                          inputOffset,
                          inputLen,
                          outputDirect,
                          outputArray,
                          outputOffset));
        } else {
          result =
              nInitUpdate(
                  opMode,
                  key,
                  key.length,
                  iv,
                  ctxContainer,
                  0,
                  inputDirect,
                  inputArray,
                  inputOffset,
                  inputLen,
                  outputDirect,
                  outputArray,
                  outputOffset);
          nativeCtx = new NativeEvpCipherCtx(ctxContainer[0]);
        }
        cipherState = CipherState.UPDATED;
      } else {
        // Cipher is in UPDATED state: this is not the first time update is being invoked.
        result =
            nativeCtx.use(
                ctxPtr ->
                    nUpdate(
                        opMode,
                        ctxPtr,
                        inputDirect,
                        inputArray,
                        inputOffset,
                        inputLen,
                        unprocessedInput,
                        outputDirect,
                        outputArray,
                        outputOffset));
        // No need to update the cipherState since it's already in UPDATED state.
      }
      final long all = inputLen + unprocessedInput;
      unprocessedInput = (int) (all - result);
      return result;
    } catch (final Exception e) {
      cipherState = CipherState.NEEDS_INITIALIZATION;
      cleanUpNativeContextIfNeeded(ctxContainer[0]);
      throw e;
    }
  }

  @Override
  protected byte[] engineDoFinal(final byte[] input, final int inputOffset, final int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    final byte[] inputNotNull = emptyIfNull(input);
    Utils.checkArrayLimits(inputNotNull, inputOffset, inputLen);
    // Since we allocate the output's memory, we only check if the cipher is in the correct state.
    finalOrUpdateStateCheck();
    final byte[] result = new byte[getOutputSizeFinal(inputLen)];
    final int resultLen = doFinal(null, inputNotNull, inputOffset, inputLen, null, result, 0);
    return resultLen == result.length ? result : Arrays.copyOf(result, resultLen);
  }

  @Override
  protected int engineDoFinal(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    final byte[] inputNotNull = emptyIfNull(input);
    Utils.checkArrayLimits(inputNotNull, inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, output.length - outputOffset);
    finalChecks(inputLen, output.length - outputOffset);

    return doFinal(null, inputNotNull, inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineDoFinal(final ByteBuffer input, final ByteBuffer output)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    finalChecks(input.remaining(), output.remaining());

    final ShimByteBuffer inputShimByteBuffer = new ShimByteBuffer(input, true);
    final ShimByteBuffer outputShimByteBuffer = new ShimByteBuffer(output, false);

    final int result =
        doFinal(
            inputShimByteBuffer.directByteBuffer,
            inputShimByteBuffer.array,
            inputShimByteBuffer.offset,
            input.remaining(),
            outputShimByteBuffer.directByteBuffer,
            outputShimByteBuffer.array,
            outputShimByteBuffer.offset);

    outputShimByteBuffer.writeBack(result);

    input.position(input.limit());
    output.position(output.position() + result);

    return result;
  }

  private void finalChecks(final int inputLen, final int outputLen) throws ShortBufferException {
    finalOrUpdateStateCheck();
    if (outputLen < getOutputSizeFinal(inputLen)) {
      throw new ShortBufferException(outputLen + "<" + getOutputSizeFinal(inputLen));
    }
  }

  // This method is used when calling engineDoFinal to ensure that output is large enough
  private int getOutputSizeFinal(final int inputLen) {
    return inputLen;
  }

  private int doFinal(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset) {

    if (inputLen > 0) {
      inputIsEmpty = false;
    }

    // There are four possibilities:
    // 1. Save context AND Cipher is in INITIALIZED state => nInitUpdateFinal(saveContext == true)
    // 2. Save context AND Cipher is in UPDATED state => nUpdateFinal(saveContext == true)
    // 3. Don't save context AND Cipher is in INITIALIZED state => nInitUpdateFinal(saveContext ==
    // false)
    // 4. Don't save context AND Cipher is in UPDATED state => nUpdateFinal(saveContext == false)

    final long[] ctxContainer = new long[] {0};
    try {
      final int result;
      if (saveContext) {
        if (cipherState == CipherState.INITIALIZED) {
          if (nativeCtx != null) {
            result =
                nativeCtx.use(
                    ctxPtr ->
                        nInitUpdateFinal(
                            opMode,
                            key,
                            key.length,
                            iv,
                            null,
                            ctxPtr,
                            true,
                            inputDirect,
                            inputArray,
                            inputOffset,
                            inputLen,
                            outputDirect,
                            outputArray,
                            outputOffset));
          } else {
            result =
                nInitUpdateFinal(
                    opMode,
                    key,
                    key.length,
                    iv,
                    ctxContainer,
                    0,
                    true,
                    inputDirect,
                    inputArray,
                    inputOffset,
                    inputLen,
                    outputDirect,
                    outputArray,
                    outputOffset);
            nativeCtx = new NativeEvpCipherCtx(ctxContainer[0]);
          }
        } else {
          // Cipher is in UPDATE state, which means update was called at least once, and it needs to
          // save the context. No need to call registerMess since the first update has already done
          // this.
          result =
              nativeCtx.use(
                  ctxPtr ->
                      nUpdateFinal(
                          opMode,
                          ctxPtr,
                          true,
                          inputDirect,
                          inputArray,
                          inputOffset,
                          inputLen,
                          unprocessedInput,
                          outputDirect,
                          outputArray,
                          outputOffset));
        }
      } else {
        // Don't need to save the context
        final long ctxPtr = nativeCtx == null ? 0 : nativeCtx.take();
        nativeCtx = null;
        if (cipherState == CipherState.INITIALIZED) {
          result =
              nInitUpdateFinal(
                  opMode,
                  key,
                  key.length,
                  iv,
                  null,
                  ctxPtr,
                  false,
                  inputDirect,
                  inputArray,
                  inputOffset,
                  inputLen,
                  outputDirect,
                  outputArray,
                  outputOffset);
        } else {
          // Cipher is in UPDATE state and don't need to save the context
          result =
              nUpdateFinal(
                  opMode,
                  ctxPtr,
                  false,
                  inputDirect,
                  inputArray,
                  inputOffset,
                  inputLen,
                  unprocessedInput,
                  outputDirect,
                  outputArray,
                  outputOffset);
        }
      }

      cipherState = CipherState.INITIALIZED;
      unprocessedInput = 0;
      inputIsEmpty = true;

      return result;

    } catch (final Exception e) {
      cipherState = CipherState.NEEDS_INITIALIZATION;
      cleanUpNativeContextIfNeeded(ctxContainer[0]);
      throw e;
    }
  }

  private void cleanUpNativeContextIfNeeded(final long ctxPtr) {
    if (nativeCtx == null && ctxPtr != 0) {
      Utils.releaseEvpCipherCtx(ctxPtr);
    }
  }

  // We have four JNI calls. Their names start with the letter n, followed by the operations that
  // they perform on the underlying EVP_CIPHER_CTX. For example, nInitUpdate calls init and update
  // on the context.

  // This method is used for one-shot operations, when engineDoFinal is invoked immediately after
  // engineInit.
  private static native int nInitUpdateFinal(
      int opMode,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      boolean saveCtx,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  // This method is used the first time engineUpdate is used in a multi-step operation.
  private static native int nInitUpdate(
      int opMode,
      byte[] key,
      int keyLen,
      byte[] iv,
      long[] ctxContainer,
      long ctxPtr,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  // This method is used the n^th time engineUpdate is used in a multi-step operation, where n >= 2.
  private static native int nUpdate(
      int opMode,
      long ctxPtr,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      int unprocessedInput,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  // This method is used  when engineDoFinal is used to finalize a multi-step operation.
  private static native int nUpdateFinal(
      int opMode,
      long ctxPtr,
      boolean saveCtx,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      int unprocessedInput,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  @Override
  protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
    try {
      final byte[] encoded = Utils.encodeForWrapping(key);
      return engineDoFinal(encoded, 0, encoded.length);
    } catch (final BadPaddingException ex) {
      // This is not reachable when encrypting.
      throw new InvalidKeyException("Wrapping failed", ex);
    }
  }

  @Override
  protected Key engineUnwrap(
      final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    try {
      final byte[] unwrappedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
      return Utils.buildUnwrappedKey(unwrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    } catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeySpecException ex) {
      throw new InvalidKeyException("Unwrapping failed", ex);
    }
  }

  private static byte[] emptyIfNull(final byte[] array) {
    return array == null ? EMPTY_ARRAY : array;
  }
}
