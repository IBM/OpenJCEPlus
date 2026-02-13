/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;

public final class BasicRandom {

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;

    public static BasicRandom getInstance(OpenJCEPlusProvider provider) {
        return new BasicRandom(provider);
    }

    private BasicRandom(OpenJCEPlusProvider provider) {
        this.provider = provider;
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
    }

    public void nextBytes(byte[] bytes) throws OCKException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            this.nativeInterface.RAND_nextBytes(bytes);
        }
    }

    public void setSeed(byte[] seed) throws OCKException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            this.nativeInterface.RAND_setSeed(seed);
        }
    }

    public byte[] generateSeed(int numBytes) throws OCKException {
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
