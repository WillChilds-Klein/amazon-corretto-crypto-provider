# Changes for AES CFB Implementation

## Added AES CFB Block Cipher Mode

This implementation adds support for the AES CFB (Cipher Feedback) block cipher mode to the Amazon Corretto Crypto Provider. The implementation includes:

1. Java implementation in `AesCfbSpi.java`
2. Native C++ implementation in `aes_cfb.cpp`
3. Service registrations in `AmazonCorrettoCryptoProvider.java`
4. Comprehensive test suite in `AesCfbTest.java`
5. Known-Answer Tests (KATs) in `AesCfbKatTest.java`

### Features

- Support for AES-128, AES-192, and AES-256 key sizes
- Support for both NoPadding and PKCS5Padding/PKCS7Padding modes
- Full compatibility with SunJCE and BouncyCastle implementations
- Comprehensive test coverage including edge cases

### Implementation Details

The AES CFB implementation follows the same pattern as the existing AES CBC implementation:

- Uses AWS-LC's EVP interface for the core cryptographic operations
- Supports both one-shot and streaming operations
- Handles ByteBuffer and byte array inputs
- Properly manages native resources

### Test Coverage

The test suite includes:
- Compatibility tests with SunJCE and BouncyCastle
- Known-Answer Tests from NIST SP 800-38A
- Edge case testing (empty inputs, various buffer sizes)
- Multi-step encryption/decryption with different processing patterns
- In-place encryption/decryption
- ByteBuffer operations with direct and non-direct buffers

### Documentation

- Updated README.md with new supported cipher modes
- Added this CHANGES.md file to document the implementation