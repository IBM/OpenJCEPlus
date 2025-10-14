/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

public final class BasicRandom {
    private NativeInterface nativeImpl;

    public static BasicRandom getInstance(boolean isFIPS) {
        return new BasicRandom(isFIPS);
    }

    private BasicRandom(boolean isFIPS) {
        this.nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
    }

    public void nextBytes(byte[] bytes) throws OCKException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            this.nativeImpl.RAND_nextBytes(bytes);
        }
    }

    public void setSeed(byte[] seed) throws OCKException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            this.nativeImpl.RAND_setSeed(seed);
        }
    }

    public byte[] generateSeed(int numBytes) throws OCKException {
        if (numBytes < 0) {
            throw new IllegalArgumentException("numBytes is negative");
        }

        byte[] seed = new byte[numBytes];
        if (numBytes > 0) {
            this.nativeImpl.RAND_generateSeed(seed);
        }
        return seed;
    }
}
