/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
