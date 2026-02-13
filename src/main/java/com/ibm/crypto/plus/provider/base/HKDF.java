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

public final class HKDF {

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final long hkdfId;
    String debPrefix = "";



    private byte[] reinitKey = null;
    int macLength = 0;

    private final String badIdMsg = "HKDF Identifier is not valid";


    public static HKDF getInstance(String digestAlgo, OpenJCEPlusProvider provider) throws OCKException {
        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        return new HKDF(digestAlgo, provider);
    }

    private HKDF(String digestAlgo, OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "HKDF (ockContext, String)";
        this.provider = provider;
        this.nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        this.hkdfId = this.nativeInterface.HKDF_create(digestAlgo);
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );

        this.provider.registerCleanable(this, cleanOCKResources(hkdfId, reinitKey, nativeInterface));
    }


    public synchronized byte[] extract(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen)
            throws OCKException {
        //final String methodName = "HKDF extract(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        //OCKDebug.Msg (debPrefix, methodName,  "saltLen:" + saltLen );
        //OCKDebug.Msg (debPrefix, methodName,  "inpKeyLen:" + inpKeyLen  + " inKey.lenth=" + inKey.length);
        byte[] extractedBytes = this.nativeInterface.HKDF_extract(hkdfId, salt,
                (long) (salt.length), inKey, inpKeyLen);
        return extractedBytes;

    }

    public synchronized byte[] expand(byte[] prkBytes, long prkLen, byte[] info, long infoLen,
            long okmLen) throws OCKException {
        //final String methodName = "HKDF expand (byte[] prkBytes, long prkLen, \r\n"
        //        + "            byte[] info, long infoLen, long okmLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        byte[] expandedBytes = this.nativeInterface.HKDF_expand(hkdfId, prkBytes,
                (long) (prkBytes.length), info, (long) (info.length), okmLen);
        return expandedBytes;

    }

    public synchronized byte[] derive(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen,
            byte[] info, long infoLen, long okmLen) throws OCKException {
        //final String methodName = "HKDFGenetateBytes(byte[] salt, long saltLen, byte[] inKey, long inpKeyLen, byte[] info, long infoLen)";
        //OCKDebug.Msg (debPrefix, methodName,  "this.hkdfId :" + this.hkdfId );
        //OCKDebug.Msg (debPrefix, methodName,  "saltLen:" + saltLen );
        //OCKDebug.Msg (debPrefix, methodName,  "inpKeyLen:" + inpKeyLen  + " inKey.lenth=" + inKey.length);
        byte[] generateBytes = this.nativeInterface.HKDF_derive(hkdfId, salt,
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
            this.macLength = this.nativeInterface.HKDF_size(hkdfId);
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId ";
        //OCKDebug.Msg (debPrefix, methodName,  "id :" + id);
        return (id != 0L);
    }

    private Runnable cleanOCKResources(long hkdfId, byte[] reinitKey, NativeInterface nativeInterface) {
        return () -> {
            try {
                if (hkdfId != 0) {
                    nativeInterface.HKDF_delete(hkdfId);
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
