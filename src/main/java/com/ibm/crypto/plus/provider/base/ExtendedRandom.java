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
    private final String algName;

    private long ockPRNGContextId;
    private boolean usingThreadLocalContext = true;

    // Defaults (in KB)
    private static final int DEFAULT_RANDOM_BYTE_CACHE_SIZE_KB = 128;
    private static final int DEFAULT_BYPASS_THRESHOLD_KB = 16;

    private static final int RANDOM_BYTE_CACHE_SIZE = Integer.getInteger("openjceplus.randomcachesize",
            DEFAULT_RANDOM_BYTE_CACHE_SIZE_KB) * 1024;

    private static final int BYPASS_THRESHOLD = Integer.getInteger("openjceplus.randombypassthreshold",
            DEFAULT_BYPASS_THRESHOLD_KB) * 1024;

    private byte[] randomByteCache;
    private int cachePos; // Next unread index in cache
    private int randomByteCacheLength;

    private static final ThreadLocal<PRNGContextPointer> prngContextBufferSha256 = new ThreadLocal<PRNGContextPointer>();
    private static final ThreadLocal<PRNGContextPointer> prngContextBufferSha512 = new ThreadLocal<PRNGContextPointer>();

    public static ExtendedRandom getInstance(String algName, OpenJCEPlusProvider provider)
            throws NativeException {
        if ((algName == null) || algName.isEmpty()) {
            throw new IllegalArgumentException("algName is null/empty");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        return new ExtendedRandom(algName, provider);
    }

    private ExtendedRandom(String algName, OpenJCEPlusProvider provider) throws NativeException {
        this.algName = algName;
        this.provider = provider;
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        this.ockPRNGContextId = getPRNGContext(algName);
    }

    private long getPRNGContext(String algName) throws NativeException {
        PRNGContextPointer prngCtx = null;
        ThreadLocal<PRNGContextPointer> prngCtxBuffer = null;

        switch (algName) {
            case "SHA256":
                prngCtxBuffer = prngContextBufferSha256;
                break;
            case "SHA512":
                prngCtxBuffer = prngContextBufferSha512;
                break;
            default:
                throw new IllegalArgumentException(
                        "Unsupported HASHDRBG algorithm: " + algName);
        }

        prngCtx = prngCtxBuffer.get();
        if (prngCtx == null) {
            prngCtx = new PRNGContextPointer(algName, this.nativeInterface, this.provider);
            prngCtxBuffer.set(prngCtx);
        }

        return prngCtx.getCtx();
    }

    public synchronized void nextBytes(byte[] bytes) throws NativeException {
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
            this.nativeInterface.EXTRAND_nextBytes(ockPRNGContextId, bytes);
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
                refillRandomByteCache();
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

    public synchronized void setSeed(byte[] seed) throws NativeException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            createInstanceContextForReSeed();
            this.nativeInterface.EXTRAND_setSeed(ockPRNGContextId, seed);
            clearRandomByteCache();
        }
    }

    private void createInstanceContextForReSeed() throws NativeException {
        if (!usingThreadLocalContext) {
            return;
        }

        long instanceCtx = this.nativeInterface.EXTRAND_create(algName);
        this.ockPRNGContextId = instanceCtx;
        this.usingThreadLocalContext = false;

        this.provider.registerCleanable(this, cleanOCKResources(instanceCtx, nativeInterface));
    }

    private static Runnable cleanOCKResources(long ockPRNGContextId, NativeInterface nativeInterface) {
        return () -> {
            try {
                if (ockPRNGContextId != 0) {
                    nativeInterface.EXTRAND_delete(ockPRNGContextId);
                }
            } catch (Exception e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }

    private static final class PRNGContextPointer {
        final long prngCtx;

        PRNGContextPointer(String algName, NativeInterface nativeInterface, OpenJCEPlusProvider provider) throws NativeException {
            this.prngCtx = nativeInterface.EXTRAND_create(algName);
            provider.registerCleanable(this, ExtendedRandom.cleanOCKResources(this.prngCtx, nativeInterface));
        }

        long getCtx() {
            return this.prngCtx;
        }
    }

    private void refillRandomByteCache() throws NativeException {
        if (randomByteCache == null) {
            randomByteCache = new byte[RANDOM_BYTE_CACHE_SIZE];
        }

        // Fill the entire cache from native.
        this.nativeInterface.EXTRAND_nextBytes(ockPRNGContextId, randomByteCache);

        cachePos = 0;
        randomByteCacheLength = randomByteCache.length;
    }

    private void clearRandomByteCache() {
        if (randomByteCache != null) {
            java.util.Arrays.fill(randomByteCache, (byte) 0);
        }
        cachePos = 0;
        randomByteCacheLength = 0;
    }
}
