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

    // 128KB cache ?
    private static final int MEGABYTE_CACHE_SIZE = 128 * 1024;

    // 16KB threshold ?
    private static final int BYPASS_THRESHOLD = 16 * 1024;

    private byte[] megaByteCache;
    private int cachePos; // Next unread index in cache
    private int megaByteCacheLength;

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
        int len = bytes.length;
        if (len == 0) {
            return;
        }

        // 1) LARGE REQUEST BYPASS:
        // Fill destination directly to avoid cache->dest copy cost.
        if (len >= BYPASS_THRESHOLD) {
            NativeInterface.EXTRAND_nextBytes(ockContext.getId(), ockPRNGContextId, bytes);

            // Invalidate cache so next small request refills fresh.
            cachePos = megaByteCacheLength = 0;
            return;
        }

        // 2) SMALL/MEDIUM REQUEST:
        // Serve from cache, refilling as needed.
        int outPos = 0;
        int remaining = len;

        while (remaining > 0) {
            int available = megaByteCacheLength - cachePos;

            // If cache is empty (or not initialized), refill it.
            if (available <= 0) {
                refillMegaByteCache();
                available = megaByteCacheLength - cachePos;
            }

            // Copy as much as we can from cache into output.
            int toCopy = Math.min(available, remaining);
            System.arraycopy(megaByteCache, cachePos, bytes, outPos, toCopy);

            cachePos += toCopy;
            outPos += toCopy;
            remaining -= toCopy;
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
        return () -> {
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

    private void refillMegaByteCache() throws OCKException {
        if (megaByteCache == null) {
            megaByteCache = new byte[MEGABYTE_CACHE_SIZE];
        }

        // Fill the entire cache from native.
        NativeInterface.EXTRAND_nextBytes(ockContext.getId(), ockPRNGContextId, megaByteCache);

        cachePos = 0;
        megaByteCacheLength = megaByteCache.length;
    }
}
