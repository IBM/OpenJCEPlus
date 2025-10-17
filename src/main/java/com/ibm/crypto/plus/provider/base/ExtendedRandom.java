/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

public final class ExtendedRandom {

    private boolean isFIPS;
    private NativeInterface nativeImpl = null;
    long ockPRNGContextId;

    public static ExtendedRandom getInstance(boolean isFIPS, String algName)
            throws OCKException {

        if ((algName == null) || algName.isEmpty()) {
            throw new IllegalArgumentException("algName is null/empty");
        }

        return new ExtendedRandom(isFIPS, algName);
    }

    private ExtendedRandom(boolean isFIPS, String algName) throws OCKException {
        this.isFIPS = isFIPS;
        this.nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        this.ockPRNGContextId = this.nativeImpl.EXTRAND_create(algName);
    }

    public synchronized void nextBytes(byte[] bytes) throws OCKException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            this.nativeImpl.EXTRAND_nextBytes(ockPRNGContextId, bytes);
        }
    }

    public synchronized void setSeed(byte[] seed) throws OCKException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            this.nativeImpl.EXTRAND_setSeed(ockPRNGContextId, seed);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            if (ockPRNGContextId != 0) {
                this.nativeImpl.EXTRAND_delete(ockPRNGContextId);
                ockPRNGContextId = 0;
            }
        } finally {
            super.finalize();
        }
    }
}
