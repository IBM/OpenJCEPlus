/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;

public final class BasicRandom {

    private OpenJCEPlusProvider provider;
    private String algName = null;
    private NativeInterface nativeInterface;

    public static BasicRandom getInstance(OpenJCEPlusProvider provider, String algName) throws NativeException {
        return new BasicRandom(provider, algName);
    }

    private BasicRandom(OpenJCEPlusProvider provider, String algName) {
        this.provider = provider;
        this.nativeInterface = NativeCryptoSelector.selectBackend(provider, "SecureRandom", algName + "DRBG");
    }

    public byte[] generateSeed(int numBytes) throws NativeException {
        if (numBytes < 0) {
            throw new IllegalArgumentException("numBytes is negative");
        }

        byte[] seed = new byte[numBytes];
        if (numBytes > 0) {
            this.nativeInterface.RAND_generateSeed(seed);
        }
        return seed;
    }
}
