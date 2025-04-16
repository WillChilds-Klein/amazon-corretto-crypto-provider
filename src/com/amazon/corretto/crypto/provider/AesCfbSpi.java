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
import java.util.function.Predicate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

class AesCfbSpi extends CipherSpi {
  // The value of padding is passed to AWS-LC and it respects EVP_CIPHER_CTX_set_padding API:
  // https://github.com/aws/aws-lc/blob/main/include/openssl/cipher.h#L294-L297
  public static final int NO_PADDING = 0;
  public static final int PKCS7_PADDING = 1;

  enum Padding {
    NONE(NO_PADDING),
    PKCS7(PKCS7_PADDING);
    private final int value;

    Padding(final int value) {
      this.value = value;
    }

    int getValue() {
      return value;
    }
  }

  public static final Set<String> AES_CFB_NO_PADDING_NAMES;
  public static final Set<String> AES_CFB_PKCS7_PADDING_NAMES;

  static {
    Loader.load();
    AES_CFB_NO_PADDING_NAMES =
        Collections.unmodifiableSet(
            new HashSet<>(
                Arrays.asList(
                    "AES/CFB/NoPadding".toLowerCase(),
                    "AES_128/CFB/NoPadding".toLowerCase(),
                    "AES_192/CFB/NoPadding".toLowerCase(),
                    "AES_256/CFB/NoPadding".toLowerCase())));

    // PKCS5Padding with AES/CFB must be treated as PKCS7Padding. PKCS7Padding name is not
    // recognized by SunJCE, but BouncyCastle supports PKCS7Padding as a valid name for the same
    // padding.
    AES_CFB_PKCS7_PADDING_NAMES =
        Collections.unmodifiableSet(
            new HashSet<>(
                Arrays.asList(
                    "AES/CFB/PKCS7Padding".toLowerCase(),
                    "AES_128/CFB/PKCS7Padding".toLowerCase(),
                    "AES_192/CFB/PKCS7Padding".toLowerCase(),
                    "AES_256/CFB/PKCS7Padding".toLowerCase(),
                    "AES/CFB/PKCS5Padding".toLowerCase(),
                    "AES_128/CFB/PKCS5Padding".toLowerCase(),
                    "AES_192/CFB/PKCS5Padding".toLowerCase(),
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
  private Padding paddingScheme;
  // CFB processes data one block at a time. There are two scenarios where not all the input passed
  // to engineUpdate is processed:
  //     1. Input length is not a multiple of the block size,
  //     2. Padding is enabled and cipher is configured for decryption.
  // This variable keeps track of the unprocessed bytes.
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
  // remains false till the cipher is done processing. This is used during decryption with padding
  // to produce empty output when nothing is passed to the cipher.
  private boolean inputIsEmpty;

  AesCfbSpi(final Padding padding, final boolean saveContext) {
    this.paddingScheme = padding;
    this.cipherState = CipherState.NEEDS_INITIALIZATION;
    this.unprocessedInput = 0;
    this.opMode = MODE_NOT_SET;
    this.key = null;
    this.iv = null;
    this.nativeCtx = null;
    this.saveContext = saveContext;
    this.inputIsEmpty = true;
  }

  private boolean noPadding() {
    return paddingScheme.equals(Padding.NONE);
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
    Predicate<String> paddingPredicate = n -> n.split("/")[2].equalsIgnoreCase(padding);
    if (AES_CFB_PKCS7_PADDING_NAMES.stream().anyMatch(paddingPredicate)) {
      this.paddingScheme = Padding.PKCS7;
    } else if (AES_CFB_NO_PADDING_NAMES.stream().anyMatch(paddingPredicate)) {
      this.paddingScheme = Padding.NONE;
    } else {
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

    final long rem = all % BLOCK_SIZE_IN_BYTES;

    // When there is no padding, the output size for enc/dec is at most all.
    if (noPadding()) {
      return (int) (all);
    }

    // If padding is enabled and encrypting, the largest output size is during doFinal
    if (opMode == ENC_MODE) {
      return (int) ((all + BLOCK_SIZE_IN_BYTES) - rem);
    }

    // If padding is enabled and decrypting, the largest output size is during doFinal
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
    final long all = ((long) inputLen) + ((long) unprocessedInput);
    if (all == 0) {
      return 0;
    }
    final long rem = all % BLOCK_SIZE_IN_BYTES;
    if (noPadding() || opMode == ENC_MODE || rem != 0) {
      return (int) (all - rem);
    }
    // When all data (inputLen + unprocessedInput) is block-size aligned, padding is enabled, and we
    // are decrypting, the cipher does not decrypt the last block until doFinal. However, AWS-LC
    // touches the last block of output, as a result, in ACCP, we must over allocate.
    return (int) all;
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
      final int evpPaddingValue = paddingScheme.getValue();
      if (cipherState == CipherState.INITIALIZED) {
        if (nativeCtx != null) {
          result =
              nativeCtx.use(
                  ctxPtr ->
                      nInitUpdate(
                          opMode,
                          evpPaddingValue,
                          key,
                          key.length,
                          iv,
                          ctxContainer,
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
                  evpPaddingValue,
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
        }
        nativeCtx = new NativeEvpCipherCtx(ctxContainer[0]);
      } else {
        result =
            nativeCtx.use(
                ctxPtr ->
                    nUpdate(
                        ctxPtr,
                        inputDirect,
                        inputArray,
                        inputOffset,
                        inputLen,
                        unprocessedInput,
                        outputDirect,
                        outputArray,
                        outputOffset));
      }
      cipherState = CipherState.UPDATED;
      unprocessedInput =
          (int) ((((long) unprocessedInput) + ((long) inputLen)) % BLOCK_SIZE_IN_BYTES);
      return result;
    } catch (final Exception e) {
      // This should not happen during update.
      throw new RuntimeCryptoException(e);
    }
  }

  @Override
  protected byte[] engineDoFinal(final byte[] input, final int inputOffset, final int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    // Since we allocate the output's memory, we only check if the cipher is in the correct state.
    finalOrUpdateStateCheck();
    final byte[] result = new byte[engineGetOutputSize(inputLen)];
    final int resultLen = doFinal(null, input, inputOffset, inputLen, null, result, 0);
    return result.length == resultLen ? result : Arrays.copyOf(result, resultLen);
  }

  @Override
  protected int engineDoFinal(
      final byte[] input,
      final int inputOffset,
      final int inputLen,
      final byte[] output,
      final int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    Utils.checkArrayLimits(input, inputOffset, inputLen);
    Utils.checkArrayLimits(output, outputOffset, output.length - outputOffset);
    doFinalChecks(inputLen, output.length - outputOffset);
    return doFinal(null, input, inputOffset, inputLen, null, output, outputOffset);
  }

  @Override
  protected int engineDoFinal(final ByteBuffer input, final ByteBuffer output)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    doFinalChecks(input.remaining(), output.remaining());

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

  private void doFinalChecks(final int inputLen, final int outputLen) throws ShortBufferException {
    finalOrUpdateStateCheck();
    if (outputLen < engineGetOutputSize(inputLen)) {
      throw new ShortBufferException();
    }
  }

  private int doFinal(
      final ByteBuffer inputDirect,
      final byte[] inputArray,
      final int inputOffset,
      final int inputLen,
      final ByteBuffer outputDirect,
      final byte[] outputArray,
      final int outputOffset)
      throws IllegalBlockSizeException, BadPaddingException {

    if (inputLen > 0) {
      inputIsEmpty = false;
    }

    try {
      final int result;
      final int evpPaddingValue = paddingScheme.getValue();
      if (cipherState == CipherState.INITIALIZED) {
        final long[] ctxContainer = new long[] {0};
        result =
            nInitUpdateFinal(
                opMode,
                evpPaddingValue,
                key,
                key.length,
                iv,
                ctxContainer,
                0,
                saveContext,
                inputDirect,
                inputArray,
                inputOffset,
                inputLen,
                outputDirect,
                outputArray,
                outputOffset);
        if (saveContext) {
          nativeCtx = new NativeEvpCipherCtx(ctxContainer[0]);
        }
      } else {
        result =
            nativeCtx.use(
                ctxPtr ->
                    nUpdateFinal(
                        ctxPtr,
                        saveContext,
                        inputDirect,
                        inputArray,
                        inputOffset,
                        inputLen,
                        unprocessedInput,
                        outputDirect,
                        outputArray,
                        outputOffset));
      }
      cipherState = CipherState.INITIALIZED;
      unprocessedInput = 0;
      return result;
    } catch (final Exception e) {
      cipherState = CipherState.NEEDS_INITIALIZATION;
      throw new RuntimeCryptoException(e);
    }
  }

  @Override
  protected byte[] engineWrap(final Key key) throws IllegalBlockSizeException, InvalidKeyException {
    try {
      return engineDoFinal(Utils.encodeForWrapping(key), 0, Utils.encodeForWrapping(key).length);
    } catch (final BadPaddingException e) {
      throw new RuntimeCryptoException(e);
    }
  }

  @Override
  protected Key engineUnwrap(
      final byte[] wrappedKey, final String wrappedKeyAlgorithm, final int wrappedKeyType)
      throws InvalidKeyException, NoSuchAlgorithmException {
    try {
      final byte[] encodedKey = engineDoFinal(wrappedKey, 0, wrappedKey.length);
      return Utils.buildUnwrappedKey(encodedKey, wrappedKeyAlgorithm, wrappedKeyType);
    } catch (final IllegalBlockSizeException | BadPaddingException e) {
      throw new InvalidKeyException(e);
    } catch (final InvalidKeySpecException e) {
      throw new InvalidKeyException("Cannot construct key from wrapped key", e);
    }
  }

  private static native int nInitUpdateFinal(
      int opMode,
      int padding,
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

  private static native int nInitUpdate(
      int opMode,
      int padding,
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

  private static native int nUpdate(
      long ctxPtr,
      ByteBuffer inputDirect,
      byte[] inputArray,
      int inputOffset,
      int inputLen,
      int unprocessed_input,
      ByteBuffer outputDirect,
      byte[] outputArray,
      int outputOffset);

  private static native int nUpdateFinal(
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
}
