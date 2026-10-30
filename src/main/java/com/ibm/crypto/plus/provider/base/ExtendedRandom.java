/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.util.IdentityHashMap;
import java.util.Map;

public final class ExtendedRandom {

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final String algName;

    /*
     * Used only when this ExtendedRandom instance owns its
     * own PRNG context, for example after setSeed().
     *
     * ThreadLocal contexts are not stored.
     */
    private long instancePRNGContextId;
    private boolean usingThreadLocalContext = true;

    /*
     * ThreadLocal caches keyed by algorithm. Each cache holds one context per
     * NativeInterface (backend) so that OCK and OpenSSL never share a native
     * pointer and alternating between backends does not recreate contexts.
     */
    private static final ThreadLocal<Map<NativeInterface, PRNGContextPointer>> prngContextBufferSha256 =
        ThreadLocal.withInitial(IdentityHashMap::new);
    private static final ThreadLocal<Map<NativeInterface, PRNGContextPointer>> prngContextBufferSha512 =
        ThreadLocal.withInitial(IdentityHashMap::new);

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
        this.nativeInterface = NativeCryptoSelector.selectBackend(provider, "SecureRandom", algName + "DRBG");
    }

    private PRNGContextPointer getThreadLocalPRNGContext() throws NativeException {
        PRNGContextPointer prngCtx = null;
        ThreadLocal<Map<NativeInterface, PRNGContextPointer>> prngCtxBuffer = null;

        switch (this.algName) {
            case "SHA256":
                prngCtxBuffer = prngContextBufferSha256;
                break;
            case "SHA512":
                prngCtxBuffer = prngContextBufferSha512;
                break;
            default:
                throw new IllegalArgumentException(
                        "Unsupported HASHDRBG algorithm: " + this.algName);
        }

        Map<NativeInterface, PRNGContextPointer> perBackend = prngCtxBuffer.get();
        prngCtx = perBackend.get(this.nativeInterface);
        if (prngCtx == null) {
            prngCtx = new PRNGContextPointer(this.algName, this.nativeInterface, this.provider);
            perBackend.put(this.nativeInterface, prngCtx);
        }

        return prngCtx;
    }

    public synchronized void nextBytes(byte[] bytes) throws NativeException {
        if (bytes == null) {
            throw new IllegalArgumentException("bytes is null");
        }

        if (bytes.length > 0) {
            if (usingThreadLocalContext) {
                PRNGContextPointer prngCtx = getThreadLocalPRNGContext();
                this.nativeInterface.EXTRAND_nextBytes(prngCtx.getCtx(), bytes);
            } else {
                this.nativeInterface.EXTRAND_nextBytes(instancePRNGContextId, bytes);
            }
        }
    }

    public synchronized void setSeed(byte[] seed) throws NativeException {
        if (seed == null) {
            throw new IllegalArgumentException("seed is null");
        }

        if (seed.length > 0) {
            // Switch from cached context to instance context for re-seeding
            if (usingThreadLocalContext) {
                this.instancePRNGContextId = createInstanceContext();
            }
            this.nativeInterface.EXTRAND_setSeed(instancePRNGContextId, seed);
        }
    }

    private long createInstanceContext() throws NativeException {
        long instanceCtx = this.nativeInterface.EXTRAND_create(algName);
        this.usingThreadLocalContext = false;
        this.provider.registerCleanable(this, cleanNativeResources(instanceCtx, nativeInterface));
        return instanceCtx;
    }

    private static Runnable cleanNativeResources(long instancePRNGContextId, NativeInterface nativeInterface) {
        return () -> {
            try {
                if (instancePRNGContextId != 0) {
                    nativeInterface.EXTRAND_delete(instancePRNGContextId);
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
            provider.registerCleanable(this, ExtendedRandom.cleanNativeResources(this.prngCtx, nativeInterface));
        }

        long getCtx() {
            return this.prngCtx;
        }
    }
}
