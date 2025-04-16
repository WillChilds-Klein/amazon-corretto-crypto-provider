Hello, today we're going to implement a new block cipher mode for AES called
AES CFB. The internal details of CFB don't really matter. You can think of it
like any other block cipher mode. You can find an example in the last block
cipher mode we implemented, AES CBC, here:

https://github.com/corretto/amazon-corretto-crypto-provider/commit/ee2fa5507fc97ec0080dc18d0d783ff1a65ea85e

Please produce an implementation of AES CFB as well as a test suite including
known-answer-tests (KATs) and maximize coverage on your new implementation. You
should call your new test file `AesCfbTest` and you can run it with:

```
./gradlew cmake_clean single_test -DSINGLE_TEST=com.amazon.corretto.crypto.provider.test.AesCfbTest
```

Before your test is written, you can check whether your code compiles with:

```
./gradlew cmake_clean build
```

For each significant step you achieve in your implementation, please make a
commit locally and append a summary notes to a local file called CHANGES.md
