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
import java.security.InvalidKeyException;
import java.security.SignatureException;

public final class SignatureEdDSA {

    private NativeInterface nativeInterface;
    private AsymmetricKey key = null;
    private boolean initialized = false;
    private final String badIdMsg = "Digest Identifier or PKey Identifier is not valid";
    private final static String debPrefix = "SIGNATURE";

    public static SignatureEdDSA getInstance(OpenJCEPlusProvider provider) throws OCKException {
        return new SignatureEdDSA(provider);
    }

    private SignatureEdDSA(OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "SignatureEdDSA(String)";
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
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
        byte[] signature = this.nativeInterface.SIGNATUREEdDSA_signOneShot(
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
        boolean verified = this.nativeInterface.SIGNATUREEdDSA_verifyOneShot(
                this.key.getPKeyId(), sigBytes, dataBytes);
        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {

        //OCKDebug.Msg (debPrefix, "validId", "id :" + id);
        return (id != 0L);
    }
}
