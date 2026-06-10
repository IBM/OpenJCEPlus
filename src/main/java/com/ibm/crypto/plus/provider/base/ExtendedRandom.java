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

    private static final boolean IS_ZOS = System.getProperty("os.name")
                                                .toLowerCase()
                                                .contains("z/os");

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final String algName;

    private long ockPRNGContextId;
    private boolean usingThreadLocalContext = true;

    private static final ThreadLocal<PRNGContextPointer> prngContextBufferSha256 =
        IS_ZOS ? null : new ThreadLocal<PRNGContextPointer>();
    private static final ThreadLocal<PRNGContextPointer> prngContextBufferSha512 =
        IS_ZOS ? null : new ThreadLocal<PRNGContextPointer>();

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
        // On z/OS, create a new instance context without caching.
        if (IS_ZOS) {
            return createInstanceContext();
        }

        // On non-z/OS platforms, use the cached context if available,
        // otherwise create and cache it.
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

        if (bytes.length > 0) {
            this.nativeInterface.EXTRAND_nextBytes(ockPRNGContextId, bytes);
        }
    }

    public synchronized void setSeed(byte[] seed) throws NativeException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            // Switch from cached context to instance context for re-seeding
            if (usingThreadLocalContext) {
                this.ockPRNGContextId = createInstanceContext();
            }
            this.nativeInterface.EXTRAND_setSeed(ockPRNGContextId, seed);
        }
    }

    private long createInstanceContext() throws NativeException {
        long instanceCtx = this.nativeInterface.EXTRAND_create(algName);
        this.usingThreadLocalContext = false;
        this.provider.registerCleanable(this, cleanOCKResources(instanceCtx, nativeInterface));
        return instanceCtx;
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
}
