/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;

public final class ExtendedRandom {

    OpenJCEPlusProvider provider;
    OCKContext ockContext;
    final long ockPRNGContextId;

    public static ExtendedRandom getInstance(OCKContext ockContext, String algName, OpenJCEPlusProvider provider)
            throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if ((algName == null) || algName.isEmpty()) {
            throw new IllegalArgumentException("algName is null/empty");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        return new ExtendedRandom(ockContext, algName, provider);
    }

    private ExtendedRandom(OCKContext ockContext, String algName, OpenJCEPlusProvider provider) throws OCKException {
        this.ockContext = ockContext;
        this.ockPRNGContextId = NativeInterface.EXTRAND_create(ockContext.getId(), algName);
        this.provider = provider;

        this.provider.registerCleanable(this, cleanOCKResources(ockPRNGContextId, ockContext));
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

    private Runnable cleanOCKResources(long ockPRNGContextId, OCKContext ockContext) {
        return() -> {
            try {
                if (ockPRNGContextId != 0) {
                    NativeInterface.EXTRAND_delete(ockContext.getId(), ockPRNGContextId);
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
