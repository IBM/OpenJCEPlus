/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.util.Arrays;

public final class HKDF {

    private boolean isFIPS;
    private NativeInterface nativeImpl = null;
    private long hkdfId = 0;
    String debPrefix = "";



    private byte[] reinitKey = null;
    int macLength = 0;

    private final String badIdMsg = "HKDF Identifier is not valid";


    public static HKDF getInstance(boolean isFIPS, String digestAlgo) throws OCKException {
        return new HKDF(isFIPS, digestAlgo);
    }

    private HKDF(boolean isFIPS, String digestAlgo) throws OCKException {
        //final String methodName = "HKDF (isFIPS, String)";
        this.isFIPS = isFIPS;
        this.nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        this.hkdfId = this.nativeImpl.HKDF_create(digestAlgo);
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
    }


    public synchronized byte[] extract(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen)
            throws OCKException {
        //final String methodName = "HKDF extract(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        //OCKDebug.Msg (debPrefix, methodName,  "saltLen:" + saltLen );
        //OCKDebug.Msg (debPrefix, methodName,  "inpKeyLen:" + inpKeyLen  + " inKey.lenth=" + inKey.length);
        byte[] extractedBytes = this.nativeImpl.HKDF_extract(hkdfId, salt,
                (long) (salt.length), inKey, inpKeyLen);
        return extractedBytes;

    }

    public synchronized byte[] expand(byte[] prkBytes, long prkLen, byte[] info, long infoLen,
            long okmLen) throws OCKException {
        //final String methodName = "HKDF expand (byte[] prkBytes, long prkLen, \r\n"
        //        + "            byte[] info, long infoLen, long okmLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        byte[] expandedBytes = this.nativeImpl.HKDF_expand(hkdfId, prkBytes,
                (long) (prkBytes.length), info, (long) (info.length), okmLen);
        return expandedBytes;

    }

    public synchronized byte[] derive(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen,
            byte[] info, long infoLen, long okmLen) throws OCKException {
        //final String methodName = "HKDFGenetateBytes(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen, byte[] info, long infoLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        //OCKDebug.Msg (debPrefix, methodName,  "saltLen:" + saltLen );
        //OCKDebug.Msg (debPrefix, methodName,  "inpKeyLen:" + inpKeyLen  + " inKey.lenth=" + inKey.length);
        byte[] generateBytes = this.nativeImpl.HKDF_derive(hkdfId, salt,
                (long) (salt.length), inKey, inpKeyLen, info, (long) (info.length), okmLen);
        return generateBytes;

    }



    public int getMacLength() throws OCKException {
        //final String methodName = "HKDF getMacLength() ";
        if (macLength == 0) {
            obtainMacLength();
        }
        //OCKDebug.Msg (debPrefix, methodName, "hkdfId :" + hkdfId + " macLength :" + macLength);
        return macLength;
    }

    public long getHKDFId() {
        //final String methodName = "getHKDFId";
        //OCKDebug.Msg (debPrefix, methodName, hkdfId);
        return hkdfId;
    }

    private synchronized void obtainMacLength() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getMacLength at the same time, we only want to call the
        // native code one time.
        //
        if (macLength == 0) {
            if (!validId(hkdfId)) {
                throw new OCKException(badIdMsg);
            }
            this.macLength = this.nativeImpl.HKDF_size(hkdfId);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize ";
        //OCKDebug.Msg (debPrefix, methodName,  "hkdfId :" + hkdfId + " hmacId : " + hmacId );
        try {
            if (hkdfId != 0) {
                this.nativeImpl.HKDF_delete(hkdfId);
                hkdfId = 0;
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
