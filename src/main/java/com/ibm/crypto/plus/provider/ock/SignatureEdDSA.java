/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public final class SignatureEdDSA {

    private OCKContext ockContext = null;
    private AsymmetricKey key = null;
    private boolean initialized = false;
    private final String badIdMsg = "Digest Identifier or PKey Identifier is not valid";
    private final static String debPrefix = "SIGNATURE";

    public static SignatureEdDSA getInstance(OCKContext ockContext) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        return new SignatureEdDSA(ockContext);
    }

    private SignatureEdDSA(OCKContext ockContext) throws OCKException {
        //final String methodName = "SignatureEdDSA(String)";
        this.ockContext = ockContext;
    }

    public void initialize(AsymmetricKey key) throws InvalidKeyException, OCKException {
        //final String methodName = "initialize";
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        this.key = key;
        this.initialized = true;
        //OCKDebug.Msg (debPrefix, methodName,  "this.key=" + key);
    }

    public synchronized byte[] sign(byte[] oneShotData) throws OCKException, SignatureException {
        if (!this.initialized) {
            throw new IllegalStateException("SignatureEdDSA not initialized");
        }
        if (!validId(this.key.getPKeyId())) {
            throw new OCKException(badIdMsg);
        }
        byte[] signature = NativeInterface.SIGNATUREEdDSA_signOneShot(this.ockContext.getId(),
                this.key.getPKeyId(), oneShotData);
        return signature;
    }

    public synchronized boolean verify(byte[] sigBytes, byte[] dataBytes) throws OCKException {
        //final String methodName = "verify";
        // create key length function and check sigbytes against key length?
        if (!this.initialized) {
            throw new IllegalStateException("SignatureEdDSA not initialized");
        }

        if (sigBytes == null) {
            throw new IllegalArgumentException("invalid signature");
        }
        if (this.key.getPKeyId() == 0L) {
            throw new OCKException(badIdMsg);
        }
        boolean verified = NativeInterface.SIGNATUREEdDSA_verifyOneShot(this.ockContext.getId(),
                this.key.getPKeyId(), sigBytes, dataBytes);
        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {

        //OCKDebug.Msg (debPrefix, "validId", "id :" + id);
        return (id != 0L);
    }
}
