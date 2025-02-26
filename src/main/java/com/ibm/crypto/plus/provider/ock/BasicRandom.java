/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

public final class BasicRandom {

    OCKContext ockContext;

    public static BasicRandom getInstance(OCKContext ockContext) {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        return new BasicRandom(ockContext);
    }

    private BasicRandom(OCKContext ockContext) {
        this.ockContext = ockContext;
    }

    public void nextBytes(byte[] bytes) throws OCKException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            NativeInterface.RAND_nextBytes(ockContext.getId(), bytes);
        }
    }

    public void setSeed(byte[] seed) throws OCKException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            NativeInterface.RAND_setSeed(ockContext.getId(), seed);
        }
    }

    public byte[] generateSeed(int numBytes) throws OCKException {
        if (numBytes < 0) {
            throw new IllegalArgumentException("numBytes is negative");
        }

        byte[] seed = new byte[numBytes];
        if (numBytes > 0) {
            NativeInterface.RAND_generateSeed(ockContext.getId(), seed);
        }
        return seed;
    }
}
