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

public final class ExtendedRandom {

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    final long ockPRNGContextId;

    public static ExtendedRandom getInstance(String algName, OpenJCEPlusProvider provider)
            throws OCKException {
        if ((algName == null) || algName.isEmpty()) {
            throw new IllegalArgumentException("algName is null/empty");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        return new ExtendedRandom(algName, provider);
    }

    private ExtendedRandom(String algName, OpenJCEPlusProvider provider) throws OCKException {
        this.provider = provider;
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        this.ockPRNGContextId = this.nativeInterface.EXTRAND_create(algName);

        this.provider.registerCleanable(this, cleanOCKResources(ockPRNGContextId, nativeInterface));
    }

    public synchronized void nextBytes(byte[] bytes) throws OCKException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            this.nativeInterface.EXTRAND_nextBytes(ockPRNGContextId, bytes);
        }
    }

    public synchronized void setSeed(byte[] seed) throws OCKException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            this.nativeInterface.EXTRAND_setSeed(ockPRNGContextId, seed);
        }
    }

    private Runnable cleanOCKResources(long ockPRNGContextId, NativeInterface nativeInterface) {
        return () -> {
            try {
                if (ockPRNGContextId != 0) {
                    nativeInterface.EXTRAND_delete(ockPRNGContextId);
                }
            } catch (Exception e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
