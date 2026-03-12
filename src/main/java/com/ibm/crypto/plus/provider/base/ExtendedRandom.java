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

    // Defaults (in KB)
    private static final int DEFAULT_RANDOM_BYTE_CACHE_SIZE_KB = 128;
    private static final int DEFAULT_BYPASS_THRESHOLD_KB = 16;

    private static final int RANDOM_BYTE_CACHE_SIZE = Integer.getInteger("openjceplus.random.cache.size",
            DEFAULT_RANDOM_BYTE_CACHE_SIZE_KB) * 1024;

    private static final int BYPASS_THRESHOLD = Integer.getInteger("openjceplus.random.bypass.threshold",
            DEFAULT_BYPASS_THRESHOLD_KB) * 1024;

    private byte[] randomByteCache;
    private int cachePos; // Next unread index in cache
    private int randomByteCacheLength;

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
            return;
        }

        // 2) SMALL/MEDIUM REQUEST:
        // Serve from cache, refilling as needed.
        int outPos = 0;
        int needed = len;

        while (needed > 0) {
            int available = randomByteCacheLength - cachePos;

            // If cache is empty (or not initialized), refill it.
            if (available <= 0) {
                refillMegaByteCache();
                available = randomByteCacheLength - cachePos;
            }

            // Copy as much as we can from cache into output.
            int toCopy = Math.min(available, needed);
            System.arraycopy(randomByteCache, cachePos, bytes, outPos, toCopy);

            cachePos += toCopy;
            outPos += toCopy;
            needed -= toCopy;
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
        if (randomByteCache == null) {
            randomByteCache = new byte[RANDOM_BYTE_CACHE_SIZE];
        }

        // Fill the entire cache from native.
        NativeInterface.EXTRAND_nextBytes(ockContext.getId(), ockPRNGContextId, randomByteCache);

        cachePos = 0;
        randomByteCacheLength = randomByteCache.length;
    }
}
