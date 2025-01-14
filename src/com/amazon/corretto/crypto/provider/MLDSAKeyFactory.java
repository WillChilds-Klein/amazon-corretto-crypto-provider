// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;



final class MLDSAKeyFactory extends EvpKeyFactory {
  MLDSAKeyFactory(AmazonCorrettoCryptoProvider provider) {
    super(EvpKeyType.MlDsa, provider);
  }

  static native int extractLevel(byte[] encoded);
}
