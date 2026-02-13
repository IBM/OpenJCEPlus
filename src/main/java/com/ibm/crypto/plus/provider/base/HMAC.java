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
import java.util.Arrays;

public final class HMAC {

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final long hmacId;
    private boolean needsReinit = false;
    private byte[] reinitKey = null;
    private int macLength = 0;
    private final String badIdMsg = "HMAC Identifier is not valid";
    private static final String debPrefix = "HAMC";

    public static HMAC getInstance(String digestAlgo, OpenJCEPlusProvider provider) throws OCKException {
        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        return new HMAC(digestAlgo, provider);
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

    private HMAC(String digestAlgo, OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "HMAC (String)";
        this.provider = provider;
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        this.hmacId = this.nativeInterface.HMAC_create(digestAlgo);
        //OCKDebug.Msg (debPrefix, methodName,  "this.hmacId :" + this.hmacId + " digestAlgo :" + digestAlgo);

        this.provider.registerCleanable(this, cleanOCKResources(hmacId, reinitKey, nativeInterface));
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
        int result = this.nativeInterface.HMAC_update(hmacId, reinitKey,
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
        int result = this.nativeInterface.HMAC_doFinal(hmacId, reinitKey,
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
            this.macLength = this.nativeInterface.HMAC_size(hmacId);
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId ";
        //OCKDebug.Msg (debPrefix, methodName,  "id :" + id);
        return (id != 0L);
    }

    private Runnable cleanOCKResources(long hmacId, byte[] reinitKey, NativeInterface nativeInterface) {
        return () -> {
            try {
                if (hmacId != 0) {
                    nativeInterface.HMAC_delete(hmacId);
                }

                if (reinitKey != null) {
                    Arrays.fill(reinitKey, (byte) 0x00);
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
