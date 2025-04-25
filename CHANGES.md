# Implementation of AES CFB Mode

## Step 1: Created the C++ implementation file
Created `csrc/aes_cfb.cpp` with the necessary JNI functions to support AES CFB mode. The implementation follows the pattern of other AES block cipher modes in the codebase, particularly AES CBC. The implementation uses AWS-LC's EVP_CIPHER API with the EVP_aes_128_cfb128() and EVP_aes_256_cfb128() ciphers.

## Step 2: Created the Java SPI implementation
Created `src/com/amazon/corretto/crypto/provider/AesCfbSpi.java` which implements the CipherSpi interface for AES CFB mode. The implementation is based on the AesCbcSpi class but simplified since CFB mode doesn't require padding.

## Step 3: Created unit tests
Created `tst/com/amazon/corretto/crypto/provider/test/AesCfbTest.java` with comprehensive tests for the AES CFB implementation, including:
- Basic encryption/decryption
- Empty input handling
- Multi-part encryption/decryption
- ByteBuffer and DirectByteBuffer support
- Invalid key/IV size handling
- Compatibility with SunJCE provider
- NIST SP 800-38A test vectors for both AES-128-CFB and AES-256-CFB

## Step 4: Added benchmark
Created `benchmarks/src/main/java/com/amazon/corretto/crypto/benchmarks/AesCfbOneShot.java` to benchmark the performance of AES CFB mode compared to SunJCE's implementation, with various key sizes and data sizes.

## Step 5: Register services and update build files
Updated `AmazonCorrettoCryptoProvider.java` to register the new AES CFB cipher services:
```java
addService("Cipher", "AES/CFB/NoPadding", "AesCfbSpi", false);
addService("Cipher", "AES_128/CFB/NoPadding", "AesCfbSpi", false);
addService("Cipher", "AES_256/CFB/NoPadding", "AesCfbSpi", false);
```

Updated `CMakeLists.txt` to include the new `aes_cfb.cpp` file in the build.

## Step 6: Fix service instantiation
Updated `getCipherSpiInstance` method in `AmazonCorrettoCryptoProvider.java` to handle AES CFB cipher instantiation. The method was missing a case to check for AES/CFB/NoPadding algorithms, which was causing the tests to fail with "No service class for Cipher/AES/CFB/NoPadding" errors.
## Step 7: Fix test assertions
Updated the test assertions in `AesCfbTest.java` for invalid key size and padding tests. The tests were using the `assertThrows` utility which was causing issues with the expected exceptions. Changed to use explicit try-catch blocks to properly handle the exceptions.
