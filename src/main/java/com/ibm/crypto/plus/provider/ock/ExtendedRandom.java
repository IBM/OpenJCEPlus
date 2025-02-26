/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

public final class ExtendedRandom {

    OCKContext ockContext;
    long ockPRNGContextId;

    public static ExtendedRandom getInstance(OCKContext ockContext, String algName)
            throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if ((algName == null) || algName.isEmpty()) {
            throw new IllegalArgumentException("algName is null/empty");
        }

        return new ExtendedRandom(ockContext, algName);
    }

    private ExtendedRandom(OCKContext ockContext, String algName) throws OCKException {
        this.ockContext = ockContext;
        this.ockPRNGContextId = NativeInterface.EXTRAND_create(ockContext.getId(), algName);
    }

    public synchronized void nextBytes(byte[] bytes) throws OCKException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            NativeInterface.EXTRAND_nextBytes(ockContext.getId(), ockPRNGContextId, bytes);
        }
    }

    public synchronized void setSeed(byte[] seed) throws OCKException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            NativeInterface.EXTRAND_setSeed(ockContext.getId(), ockPRNGContextId, seed);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            if (ockPRNGContextId != 0) {
                NativeInterface.EXTRAND_delete(ockContext.getId(), ockPRNGContextId);
                ockPRNGContextId = 0;
            }
        } finally {
            super.finalize();
        }
    }
}
