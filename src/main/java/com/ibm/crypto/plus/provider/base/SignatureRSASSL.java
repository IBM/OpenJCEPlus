/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.security.InvalidKeyException;

//------------------------------------------------------------------------------
// NOTE:
//
// This implementation uses the ICC methods ICC_RSA_sign and ICC_RSA_verify
// methods, which requires the digest to be exactly 36 bytes.
//
// This implementation differs from the RSAforSSL algorithm in OpenJCEPlus
// which processes at most 36 bytes for the digest.
//
// At the current time this implementation is not used by the OpenJCEPlus
// provider.
//------------------------------------------------------------------------------

/**
 * This class implements the RSA signature algorithm using a pre-computed hash
 * and is specific for SSL usage which uses a digest of 36 bytes.
 */
public final class SignatureRSASSL {

    private OCKContext ockContext = null;
    private RSAKey key = null;
    private boolean convertKey = false;
    private boolean initialized = false;
    private static final String debPrefix = "SignatureRSASSL";
    private final String badIdMsg = "RSA Key Identifier is not valid";

    public static SignatureRSASSL getInstance(OCKContext ockContext) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        return new SignatureRSASSL(ockContext);
    }

    private SignatureRSASSL(OCKContext ockContext) throws OCKException {
        this.ockContext = ockContext;
    }

    public void initialize(RSAKey key, boolean convert) throws InvalidKeyException, OCKException {
        //final String methodName = "initialize";
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        this.key = key;
        this.convertKey = convert;
        this.initialized = true;
        //OCKDebug.Msg (debPrefix, methodName, "this.key :", this.key);
    }

    public synchronized byte[] sign(byte[] digest) throws OCKException {
        //final String methodName = "sign";
        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        if (digest == null) {
            throw new IllegalArgumentException("invalid digest");
        }

        //OCKDebug.Msg (debPrefix, methodName,  "RSAKeyId=" + this.key.getRSAKeyId() + " digest :",  digest);
        if (!validId(this.key.getRSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        byte[] signature = NativeInterface.RSASSL_SIGNATURE_sign(this.ockContext.getId(), digest,
                this.key.getRSAKeyId());
        //OCKDebug.Msg (debPrefix, methodName,  "signature :", signature);
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

        //OCKDebug.Msg(debPrefix, methodName, "RSAKeyId :" + this.key.getRSAKeyId() + " digest", digest);
        //OCKDebug.Msg(debPrefix, methodName, "sigBytes :",  sigBytes);

        boolean verified = NativeInterface.RSASSL_SIGNATURE_verify(this.ockContext.getId(), digest,
                this.key.getRSAKeyId(), sigBytes, convertKey);
        if (!validId(this.key.getRSAKeyId())) {
            throw new OCKException(badIdMsg);
        }
        //OCKDebug.Msg(debPrefix, methodName, "verified=" + verified);
        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "id :" + id);
        return (id != 0L);
    }

}
