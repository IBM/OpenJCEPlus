/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.util.Arrays;

public final class HMAC {

    private OCKContext ockContext = null;
    private long hmacId = 0;
    private boolean needsReinit = false;
    private byte[] reinitKey = null;
    private int macLength = 0;
    private final String badIdMsg = "HMAC Identifier is not valid";
    private static final String debPrefix = "HAMC";

    public static HMAC getInstance(OCKContext ockContext, String digestAlgo) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        return new HMAC(ockContext, digestAlgo);
    }

    static void throwOCKException(int errorCode) throws OCKException {
        switch (errorCode) {
            case -1:
                throw new OCKException("ICC_HMAC_Init failed!");
            case -2:
                throw new OCKException("ICC_HMAC_Update failed!");
            case -3:
                throw new OCKException("ICC_HMAC_Final failed!");
            default:
                throw new OCKException("Unknow Error Code");
        }
    }

    private HMAC(OCKContext ockContext, String digestAlgo) throws OCKException {
        //final String methodName = "HMAC (String)";
        this.ockContext = ockContext;
        this.hmacId = NativeInterface.HMAC_create(ockContext.getId(), digestAlgo);
        //OCKDebug.Msg (debPrefix, methodName,  "this.hmacId :" + this.hmacId + " digestAlgo :" + digestAlgo);
    }

    public synchronized void initialize(byte[] key) throws OCKException {
        //final String methodName = "HMAC initialize ";
        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }
        //OCKDebug.Msg(debPrefix, methodName, "hmacId :" + hmacId + " key :", key);
        if (!validId(hmacId)) {
            throw new OCKException(badIdMsg);
        }

        if (key != reinitKey) {
            if (reinitKey != null) {
                Arrays.fill(reinitKey, (byte) 0x00);
            }
            this.reinitKey = key.clone();
        }
        needsReinit = true;
    }

    public int getMacLength() throws OCKException {
        //final String methodName = "HMAC getMacLength() ";
        if (macLength == 0) {
            obtainMacLength();
        }
        //OCKDebug.Msg (debPrefix, methodName, "hmacId :" + hmacId + " macLength :" + macLength);
        return macLength;
    }

    public synchronized void update(byte[] input, int inputOffset, int inputLen)
            throws OCKException {
        //final String methodName = "update";
        if (this.reinitKey == null) {
            throw new IllegalStateException("HMAC not initialized");
        }

        if (inputLen == 0) {
            return;
        }

        if (input == null || inputLen < 0 || inputOffset < 0
                || (inputOffset + inputLen) > input.length) {
            throw new IllegalArgumentException("Input range is invalid");
        }
        //OCKDebug.Msg (debPrefix, methodName,  "hmacId :" + hmacId + " inputOffset :" + inputOffset + " inputLen :" + inputLen );
        if (!validId(hmacId)) {
            throw new OCKException(badIdMsg);
        }
        int result = NativeInterface.HMAC_update(ockContext.getId(), hmacId, reinitKey,
                reinitKey.length, input, inputOffset, inputLen, needsReinit);
        if (result < 0) {
            throwOCKException(result);
        }
        this.needsReinit = false;
    }

    public synchronized byte[] doFinal() throws OCKException {
        //final String methodName = "doFinal";
        if (reinitKey == null) {
            throw new IllegalStateException("HMAC not initialized");
        }

        //OCKDebug.Msg (debPrefix, methodName, "hmacId :" + hmacId);
        if (!validId(hmacId)) {
            throw new OCKException(badIdMsg);
        }
        obtainMacLength();
        byte[] hmac = new byte[macLength];
        int result = NativeInterface.HMAC_doFinal(ockContext.getId(), hmacId, reinitKey,
                reinitKey.length, hmac, needsReinit);
        if (result < 0) {
            throwOCKException(result);
        }
        // Need to reset the object such that it can be re-used.
        //
        needsReinit = true;
        //OCKDebug.Msg (debPrefix, methodName,  "hmacBytes :", hmac);
        return hmac;
    }

    public synchronized void reset() throws OCKException {
        needsReinit = true;
    }

    private synchronized void obtainMacLength() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getMacLength at the same time, we only want to call the
        // native code one time.
        //
        if (macLength == 0) {
            if (!validId(hmacId)) {
                throw new OCKException(badIdMsg);
            }
            this.macLength = NativeInterface.HMAC_size(ockContext.getId(), hmacId);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize ";
        //OCKDebug.Msg (debPrefix, methodName,  "hamcId :" + hmacId + " reinitKey :" + reinitKey);
        try {
            if (hmacId != 0) {
                NativeInterface.HMAC_delete(ockContext.getId(), hmacId);
                hmacId = 0;
            }
        } finally {
            if (reinitKey != null) {
                Arrays.fill(reinitKey, (byte) 0x00);
                reinitKey = null;
            }

            super.finalize();
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId ";
        //OCKDebug.Msg (debPrefix, methodName,  "id :" + id);
        return (id != 0L);
    }
}
