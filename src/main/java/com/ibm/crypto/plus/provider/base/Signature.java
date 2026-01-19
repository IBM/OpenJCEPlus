/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.security.InvalidKeyException;

public final class Signature {

    private OCKContext ockContext = null;
    private Digest digest = null;
    private AsymmetricKey key = null;
    private boolean initialized = false;
    private boolean convertKey = false;
    private final String badIdMsg = "Digest Identifier or PKey Identifier is not valid";
    private final static String debPrefix = "SIGNATURE";

    public static Signature getInstance(OCKContext ockContext, String digestAlgo, OpenJCEPlusProvider provider)
            throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        return new Signature(ockContext, digestAlgo, provider);
    }


    private Signature(OCKContext ockContext, String digestAlgo, OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "Signature(String)";
        this.ockContext = ockContext;
        this.digest = Digest.getInstance(ockContext, digestAlgo, provider);
        //OCKDebug.Msg (debPrefix, methodName, "digestAlgo :" + digestAlgo);
    }

    public void update(byte[] input, int offset, int length) throws OCKException {
        if ((input == null) || (length < 0) || (offset < 0) || ((offset + length) > input.length)) {
            throw new IllegalArgumentException("Bad input parameters to Signature update");
        }

        this.digest.update(input, offset, length);
    }

    public void initialize(AsymmetricKey key, boolean rsaPlain)
            throws InvalidKeyException, OCKException {
        //final String methodName = "initialize";
        if (key == null) {
            throw new IllegalArgumentException("key is null");
        }

        // Do necessary clean up before doing this. Just in case the object is reused.
        this.digest.reset();

        this.key = key;
        this.initialized = true;
        this.convertKey = rsaPlain;
        //OCKDebug.Msg (debPrefix, methodName,  "this.key=" + key);
    }

    public synchronized byte[] sign() throws OCKException {

        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        //OCKDebug.Msg (debPrefix, "sign", "digestId :" + digest.getId() + " pkeyId :" + this.key.getPKeyId());
        if ((this.digest == null) || !validId(this.digest.getId())
                || !validId(this.key.getPKeyId())) {
            throw new OCKException(badIdMsg);
        }

        byte[] signature = null;
        try {
            signature = NativeInterface.SIGNATURE_sign(this.ockContext.getId(), digest.getId(),
                    this.key.getPKeyId(), this.convertKey);
        } finally {
            // Try to reset even if OCKException is thrown
            this.digest.reset();
        }

        //OCKDebug.Msg (debPrefix, "sign",  "signature :" + signature);
        return signature;
    }

    public synchronized boolean verify(byte[] sigBytes) throws OCKException {
        //final String methodName = "verify";
        // create key length function and check sigbytes against key length?
        if (!this.initialized) {
            throw new IllegalStateException("Signature not initialized");
        }

        if (sigBytes == null) {
            throw new IllegalArgumentException("invalid signature");
        }
        //OCKDebug.Msg (debPrefix, methodName,  "digestId :" + digest.getId() + " pkeyId :" + this.key.getPKeyId());
        //OCKDebug.Msg (debPrefix, methodName,  " sigBytes :",  sigBytes);
        if ((this.digest == null) || digest.getId() == 0L || this.key.getPKeyId() == 0L) {
            throw new OCKException(badIdMsg);
        }

        boolean verified = false;
        try {
            verified = NativeInterface.SIGNATURE_verify(this.ockContext.getId(), digest.getId(),
                    this.key.getPKeyId(), sigBytes);
        } finally {
            // Try to reset even if OCKException is thrown
            this.digest.reset();
        }

        //        if (!verified) {
        //            OCKDebug.Msg (debPrefix, methodName,  "Failed to verify Signature."); 
        //        }

        return verified;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {

        //OCKDebug.Msg (debPrefix, "validId", "id :" + id);
        return (id != 0L);
    }
}
