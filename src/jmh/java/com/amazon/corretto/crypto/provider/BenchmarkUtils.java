// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

class BenchmarkUtils {
  private BenchmarkUtils() {}

  private static final SecureRandom sr = new SecureRandom();
  static final String BC_PROVIDER_NAME =
      AmazonCorrettoCryptoProvider.INSTANCE.isFips() ? "BCFIPS" : "BC";
  private static final Provider[] DEFAULT_PROVIDERS = Security.getProviders();
  private static final Set<String> NON_DEFAULT_PROVIDERS =
      new HashSet(Arrays.asList("BC", "BCFIPS", "AmazonCorrettoCryptoProvider"));

  static {
    for (Provider provider : DEFAULT_PROVIDERS) {
      if (NON_DEFAULT_PROVIDERS.contains(provider.getName())) {
        throw new RuntimeException("Provider prematurely (statically) registered: " + provider);
      }
    }
  }

  static byte[] getRandBytes(int n) {
    byte[] ret = new byte[n];
    final int bcMaxSize = 32768;
    for (int ii = 0; ii < n; ii += bcMaxSize) {
      byte[] data = new byte[bcMaxSize];
      sr.nextBytes(data);
      System.arraycopy(data, 0, ret, ii, Math.min(bcMaxSize, n - ii));
    }
    return ret;
  }

  static void setupProvider(String providerName) {
    removeAllProviders();
    final Provider bcProvider;
    try {
      bcProvider =
          (Provider)
              Class.forName(
                      AmazonCorrettoCryptoProvider.INSTANCE.isFips()
                          // ? "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"
                          // : "org.bouncycastle.jce.provider.BouncyCastleProvider")
                          ? "org.bouncycastle.jce.provider.BouncyCastleProvider"
                          : "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider")
                  .getConstructor()
                  .newInstance();
    } catch (Throwable t) {
      throw new RuntimeException(t);
    }

    switch (providerName) {
      case "AmazonCorrettoCryptoProvider":
        installDefaultProviders();
        AmazonCorrettoCryptoProvider.install();
        AmazonCorrettoCryptoProvider.INSTANCE.assertHealthy();
        if (!AmazonCorrettoCryptoProvider.INSTANCE.isFips()) {
          throw new RuntimeException("ACCP is not in FIPS mode");
        }
        break;
      case "BC":
      case "BCFIPS":
        Security.insertProviderAt(bcProvider, 1);
        break;
      case "SUN":
      case "SunEC":
      case "SunJCE":
      case "SunRsaSign":
        installDefaultProviders();
        break;
      default:
        throw new RuntimeException("Unrecognized provider: " + providerName);
    }
  }

  static String getProviderName(String providerName) {
    switch (providerName) {
      case "BC":
      case "BCFIPS":
        // return AmazonCorrettoCryptoProvider.INSTANCE.isFips() ? "BCFIPS" : "BC";
        return "BCFIPS";
      default:
        return providerName;
    }
  }

  static void installDefaultProviders() {
    for (Provider provider : DEFAULT_PROVIDERS) {
      Security.addProvider(provider);
    }
  }

  static void removeAllProviders() {
    for (Provider provider : Security.getProviders()) {
      Security.removeProvider(provider.getName());
    }
  }
}
