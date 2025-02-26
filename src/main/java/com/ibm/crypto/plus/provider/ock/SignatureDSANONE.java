/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.security.InvalidKeyException;

/**
 * This class implements the DSA signature algorithm using a pre-computed hash.
 */
public final class SignatureDSANONE {

    private OCKContext ockContext = null;
    private DSAKey key = null;
    private boolean initialized = false;
    private final static String debPrefix = "SignatureDSANONE";
    private final static String badIdMsg = "DSA Key Identifier is not valid";


    public static SignatureDSANONE getInstance(OCKContext ockContext) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        return new SignatureDSANONE(ockContext);
    }

    private SignatureDSANONE(OCKContext ockContext) throws OCKException {
        this.ockContext = ockContext;
    }

    public void initialize(DSAKey key) throws InvalidKeyException, OCKException {
        //final String methodName = "initialize";
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        this.key = key;
        this.initialized = true;
        //OCKDebug.Msg (debPrefix, methodName, "this.key=",  this.key);
    }

    public synchronized byte[] sign(byte[] digest) throws OCKException {
        //final String methodName = "sign";
        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        if (digest == null) {
            throw new IllegalArgumentException("invalid digest");
        }

        //OCKDebug.Msg(debPrefix, methodName, "this.key.DSAKeyId :" + this.key.getDSAKeyId() + " digest :", digest);
        if (!validId(this.key.getDSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        byte[] signature = NativeInterface.DSANONE_SIGNATURE_sign(this.ockContext.getId(), digest,
                this.key.getDSAKeyId());
        //OCKDebug.Msg(debPrefix, methodName, "signature :", signature);
        return signature;
    }

    public synchronized boolean verify(byte[] digest, byte[] sigBytes) throws OCKException {
        //final String methodName = "verify";
        // create key length function and check sigbytes against key length?
        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        if (digest == null) {
            throw new IllegalArgumentException("invalid digest");
        }

        if (sigBytes == null) {
            throw new IllegalArgumentException("invalid signature");
        }

        //OCKDebug.Msg(debPrefix, methodName, "this.key.DSAKeyId :" + this.key.getDSAKeyId() + " digest :",   digest);
        //OCKDebug.Msg(debPrefix, methodName, "sigBytes :",  sigBytes);
        if (!validId(this.key.getDSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        boolean verified = NativeInterface.DSANONE_SIGNATURE_verify(this.ockContext.getId(), digest,
                this.key.getDSAKeyId(), sigBytes);
        //        if (!verified) {
        //            OCKDebug.Msg (debPrefix, methodName, "Failed to verify signature.");
        //        }
        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "id :" + id);
        return (id != 0L);
    }
}
