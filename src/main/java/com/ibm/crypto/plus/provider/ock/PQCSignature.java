/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.security.InvalidKeyException;

/**
 * This code is used to do Signature Operations on ML-DSA and SLH-DSA keys.
 * These are both PQC algorithms and by definition do not support any kind 
 * of update operation.
 * 
 * Since, Java supports the idea of update as part of it's Signature framework
 * We will just save the data in a buffer if an update operation is preformed and 
 * do the doFinal as one large buffer.
 */
public final class PQCSignature {

    private OCKContext ockContext = null;
    private AsymmetricKey key = null;
    private boolean initialized = false;

    public static PQCSignature getInstance(OCKContext ockContext)
            throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        return new PQCSignature(ockContext);
    }


    private PQCSignature(OCKContext ockContext) throws OCKException {
        //final String methodName = "Signature(String)";
        this.ockContext = ockContext;
        //OCKDebug.Msg (debPrefix, methodName, "digestAlgo :" + digestAlgo);
    }

    public void initialize(AsymmetricKey key)
            throws InvalidKeyException, OCKException {
        //final String methodName = "initialize";
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        // Do necessary clean up before doing this. Just in case the object is reused.

        this.key = key;
        this.initialized = true;
        //OCKDebug.Msg (debPrefix, methodName,  "this.key=" + key);
    }

    public synchronized byte[] sign(byte [] data) throws OCKException {

        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        //OCKDebug.Msg (debPrefix, "sign"," pkeyId :" + this.key.getPKeyId());

       // if (!validId(this.key.getPKeyId())) {
       //     throw new OCKException(badIdMsg);
       // }

        byte[] signature = null;

        signature = NativeInterface.PQC_SIGNATURE_sign(this.ockContext.getId(),
        this.key.getPKeyId(), data);

        //OCKDebug.Msg (debPrefix, "sign",  "signature :" + signature);
        return signature;
    }

    public synchronized boolean verify(byte[] sigBytes, byte[] data) throws OCKException {
        //final String methodName = "verify";
        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        if (null == sigBytes || null == data) {
            throw new IllegalArgumentException("invalid signature");
        }
        boolean verified = false;

        verified = NativeInterface.PQC_SIGNATURE_verify(this.ockContext.getId(),
                                                        this.key.getPKeyId(),sigBytes, data);

        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {

        //OCKDebug.Msg (debPrefix, "validId", "id :" + id);
        return (id != 0L);
    }

}
