/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.util.Arrays;

public final class HKDF {

    private OpenJCEPlusProvider provider;
    private OCKContext ockContext = null;
    private final long hkdfId;
    String debPrefix = "";



    private byte[] reinitKey = null;
    int macLength = 0;

    private final String badIdMsg = "HKDF Identifier is not valid";


    public static HKDF getInstance(OCKContext ockContext, String digestAlgo, OpenJCEPlusProvider provider) throws OCKException {
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        return new HKDF(ockContext, digestAlgo, provider);
    }

    private HKDF(OCKContext ockContext, String digestAlgo, OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "HKDF (ockContext, String)";
        this.ockContext = ockContext;
        this.hkdfId = NativeInterface.HKDF_create(ockContext.getId(), digestAlgo);
        this.provider = provider;
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );

        this.provider.registerCleanable(this, cleanOCKResources(hkdfId, reinitKey, ockContext));
    }


    public synchronized byte[] extract(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen)
            throws OCKException {
        //final String methodName = "HKDF extract(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        //OCKDebug.Msg (debPrefix, methodName,  "saltLen:" + saltLen );
        //OCKDebug.Msg (debPrefix, methodName,  "inpKeyLen:" + inpKeyLen  + " inKey.lenth=" + inKey.length);
        byte[] extractedBytes = NativeInterface.HKDF_extract(ockContext.getId(), hkdfId, salt,
                (long) (salt.length), inKey, inpKeyLen);
        return extractedBytes;

    }

    public synchronized byte[] expand(byte[] prkBytes, long prkLen, byte[] info, long infoLen,
            long okmLen) throws OCKException {
        //final String methodName = "HKDF expand (byte[] prkBytes, long prkLen, \r\n"
        //        + "            byte[] info, long infoLen, long okmLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        byte[] expandedBytes = NativeInterface.HKDF_expand(ockContext.getId(), hkdfId, prkBytes,
                (long) (prkBytes.length), info, (long) (info.length), okmLen);
        return expandedBytes;

    }

    public synchronized byte[] derive(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen,
            byte[] info, long infoLen, long okmLen) throws OCKException {
        //final String methodName = "HKDFGenetateBytes(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen, byte[] info, long infoLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        //OCKDebug.Msg (debPrefix, methodName,  "saltLen:" + saltLen );
        //OCKDebug.Msg (debPrefix, methodName,  "inpKeyLen:" + inpKeyLen  + " inKey.lenth=" + inKey.length);
        byte[] generateBytes = NativeInterface.HKDF_derive(ockContext.getId(), hkdfId, salt,
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
            this.macLength = NativeInterface.HKDF_size(ockContext.getId(), hkdfId);
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId ";
        //OCKDebug.Msg (debPrefix, methodName,  "id :" + id);
        return (id != 0L);
    }

    private Runnable cleanOCKResources(long hkdfId, byte[] reinitKey, OCKContext ockContext) {
        return() -> {
            try {
                if (hkdfId != 0) {
                    NativeInterface.HKDF_delete(ockContext.getId(), hkdfId);
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
