/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.security.InvalidKeyException;

/**
 * This code is used to do Signature Operations on ML-DSA and SLH-DSA keys.
 * These are both PQC algorithms and by definition do not support any kind 
 * of update operation.
 * 
 * Since, Java supports the idea of update as part of it's Signature framework
 * We will just save the data in a buffer if an update operation is performed and 
 * do the doFinal as one large buffer.
 */
public final class PQCSignature {

    private NativeInterface nativeInterface;
    private AsymmetricKey key = null;
    private boolean initialized = false;
    private OpenJCEPlusProvider provider = null;

    public static PQCSignature getInstance(OpenJCEPlusProvider provider)
            throws NativeException {
        return new PQCSignature(provider);
    }

    private PQCSignature(OpenJCEPlusProvider provider) throws NativeException {
        this.provider = provider;
    }

    public void initialize(AsymmetricKey key, String algName)
            throws InvalidKeyException, NativeException {
        //final String methodName = "initialize";
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        this.key = key;
        this.initialized = true;
        this.nativeInterface = NativeCryptoSelector.selectBackend(provider, "Signature", algName);
    }

    public synchronized byte[] sign(byte[] data) throws NativeException {

        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        byte[] signature = null;

        if (data == null || data.length == 0) {
            throw new NativeException("No data to sign.");
        }

        signature = this.nativeInterface.PQC_SIGNATURE_sign(this.key.getPKeyId(), data);

        return signature;
    }

    public synchronized boolean verify(byte[] sigBytes, byte[] data) throws NativeException {
        //final String methodName = "verify";
        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        if (null == sigBytes || null == data) {
            throw new IllegalArgumentException("invalid signature");
        }
        boolean verified = false;

        verified = this.nativeInterface.PQC_SIGNATURE_verify(this.key.getPKeyId(), sigBytes, data);

        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {

        //OCKDebug.Msg (debPrefix, "validId", "id :" + id);
        return (id != 0L);
    }

}
