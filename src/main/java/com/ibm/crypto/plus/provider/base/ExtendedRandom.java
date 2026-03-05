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

    private static final ThreadLocal<PRNGContextPointer> prngContextBufferSha256 = new ThreadLocal<PRNGContextPointer>();
    private static final ThreadLocal<PRNGContextPointer> prngContextBufferSha512 = new ThreadLocal<PRNGContextPointer>();

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

        long ctxId = getPRNGContext(ockContext, algName, provider);
        return new ExtendedRandom(ockContext, ctxId, provider);
    }

    private ExtendedRandom(OCKContext ockContext, long ockPRNGContextId, OpenJCEPlusProvider provider) {
        this.ockContext = ockContext;
        this.ockPRNGContextId = ockPRNGContextId;
        this.provider = provider;
    }

    private static long getPRNGContext(OCKContext ockContext, String algName, OpenJCEPlusProvider provider)
            throws OCKException {

        PRNGContextPointer prngCtx = null;
        ThreadLocal<PRNGContextPointer> prngCtxBufer = null;

        switch (algName) {
            case "SHA256":
                prngCtxBufer = prngContextBufferSha256;
                break;
            case "SHA512":
                prngCtxBufer = prngContextBufferSha512;
                break;
            default:
                throw new IllegalArgumentException(
                        "Unsupported HASHDRBG algorithm: " + algName);
        }

        prngCtx = prngCtxBufer.get();
        if (prngCtx == null) {
            prngCtx = new PRNGContextPointer(ockContext.getId(), algName, provider);
            prngCtxBufer.set(prngCtx);
        }
        return prngCtx.getCtx();
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

    static class PRNGContextPointer {
        OpenJCEPlusProvider provider;
        final long prngCtx;
        long ockContext = 0;

        PRNGContextPointer(long ockContext, String algName, OpenJCEPlusProvider provider) throws OCKException {
            this.prngCtx = NativeInterface.EXTRAND_create(ockContext, algName);
            this.ockContext = ockContext;
            this.provider = provider;

            this.provider.registerCleanable(this, cleanOCKResources(prngCtx, ockContext));
        }

        long getCtx() {
            return prngCtx;
        }

        private Runnable cleanOCKResources(long ockPRNGContextId, long ockContext) {
            return () -> {
                try {
                    if (ockPRNGContextId != 0) {
                        NativeInterface.EXTRAND_delete(ockContext, ockPRNGContextId);
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
}
