/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.util.Arrays;

public final class DSAKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private boolean isFIPS;
    private NativeInterface nativeImpl = null;
    private long dsaKeyId;
    private long pkeyId;
    private byte[] parameters;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private static final String badIdMsg = "DSA Key Identifier is not valid";
    private final static String debPrefix = "DSAKey";

    public static DSAKey generateKeyPair(boolean isFIPS, int numBits) throws OCKException {
        //final String methodName = "generateKeyPair(numBits) ";
        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dsaKeyId = nativeImpl.DSAKEY_generate(numBits);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }
        //OCKDebug.Msg (debPrefix, methodName, "dsaKeyId=" + dsaKeyId);
        return new DSAKey(isFIPS, dsaKeyId, null, unobtainedKeyBytes, unobtainedKeyBytes);
    }

    public static byte[] generateParameters(boolean isFIPS, int numBits)
            throws OCKException {
        //final String methodName = "generateParameters(numBits) ";
        byte[] paramBytes = null;

        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }
        //OCKDebug.Msg (debPrefix, methodName, "numBits=" + numBits);
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        paramBytes = nativeImpl.DSAKEY_generateParameters(numBits);
        if (paramBytes == null) {
            throw new OCKException("The generated DSA parameter bytes are incorrect.");
        }
        return paramBytes;
    }

    public static DSAKey generateKeyPair(boolean isFIPS, byte[] parameters)
            throws OCKException {
        //final String methodName = "generateKeyPair";

        if (parameters == null || parameters.length == 0) {
            throw new IllegalArgumentException("DSA parameters are null/empty");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dsaKeyId = nativeImpl.DSAKEY_generate(parameters);
        //OCKDebug.Msg (debPrefix, methodName, "dsaKeyId=" + dsaKeyId);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }
        return new DSAKey(isFIPS, dsaKeyId, parameters.clone(), unobtainedKeyBytes,
                unobtainedKeyBytes);
    }

    public static DSAKey createPrivateKey(boolean isFIPS, byte[] privateKeyBytes)
            throws OCKException {
        //final String methodName = "createPrivateKey ";

        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dsaKeyId = nativeImpl.DSAKEY_createPrivateKey(privateKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "dsakKeyId=" + dsaKeyId);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }
        return new DSAKey(isFIPS, dsaKeyId, null, privateKeyBytes.clone(), null);
    }

    public static DSAKey createPublicKey(boolean isFIPS, byte[] publicKeyBytes)
            throws OCKException {
        //final String methodName = "createPublicKey";

        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dsaKeyId = nativeImpl.DSAKEY_createPublicKey(publicKeyBytes);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }
        //OCKDebug.Msg (debPrefix, methodName, "dsakKeyId=" + dsaKeyId);
        return new DSAKey(isFIPS, dsaKeyId, null, null, publicKeyBytes.clone());
    }

    private DSAKey(boolean isFIPS, long dsaKeyId, byte[] parameters, byte[] privateKeyBytes,
            byte[] publicKeyBytes) {
        this.isFIPS = isFIPS;
        this.nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        this.dsaKeyId = dsaKeyId;
        this.pkeyId = 0;
        this.parameters = parameters;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    public long getDSAKeyId() {
        //final String methodName = "getDSAKeyId";
        //OCKDebug.Msg (debPrefix, methodName, dsaKeyId);
        return dsaKeyId;
    }

    @Override
    public long getPKeyId() throws OCKException {
        //final String methodName = "getPKeyId";
        if (pkeyId == 0) {
            obtainPKeyId();
        }
        //OCKDebug.Msg (debPrefix, methodName, pkeyId);
        return pkeyId;
    }

    public byte[] getParameters() throws OCKException {
        //final String methodName = "getParameters";
        if (parameters == null) {
            obtainParameters();
        }
        //OCKDebug.Msg (debPrefix, methodName,parameters);

        return (parameters == null) ? null : parameters.clone();
    }

    @Override
    public byte[] getPrivateKeyBytes() throws OCKException {
        //final String methodName = "getPrivateKeyBytes";
        if (privateKeyBytes == unobtainedKeyBytes) {
            obtainPrivateKeyBytes();
        }
        //OCKDebug.Msg (debPrefix, methodName, this.privateKeyBytes);
        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    @Override
    public byte[] getPublicKeyBytes() throws OCKException {
        //final String methodName = "getPublicKeyBytes";
        if (publicKeyBytes == unobtainedKeyBytes) {
            obtainPublicKeyBytes();
        }
        //OCKDebug.Msg (debPrefix, methodName, this.publicKeyBytes);
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    private synchronized void obtainPKeyId() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPKeyId at the same time, we only want to call the native
        // code one time.
        //
        if (pkeyId == 0) {
            if (!validId(dsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.pkeyId = this.nativeImpl.DSAKEY_createPKey(dsaKeyId);
            if (!validId(pkeyId)) {
                throw new OCKException(badIdMsg);
            }
        }

    }

    private synchronized void obtainParameters() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getParameters at the same time, we only want to call the
        // native code one time.
        //
        //final String methodName = "obtainParameters";
        if (parameters == null) {
            if (!validId(dsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.parameters = this.nativeImpl.DSAKEY_getParameters(dsaKeyId);
        }
    }

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        //final String methodName = "obtainPrivateKeyBytes";
        if (privateKeyBytes == unobtainedKeyBytes) {
            if (!validId(dsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.privateKeyBytes = this.nativeImpl.DSAKEY_getPrivateKeyBytes(dsaKeyId);
        }
    }

    private synchronized void obtainPublicKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        //final String methodName = "obtainPublicKeyBytes";
        if (publicKeyBytes == unobtainedKeyBytes) {
            if (!validId(dsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.publicKeyBytes = this.nativeImpl.DSAKEY_getPublicKeyBytes(dsaKeyId);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize";
        //OCKDebug.Msg (debPrefix, methodName,  "dsaKeyId :" + dsaKeyId + " pkeyId :" + pkeyId);
        try {
            if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                Arrays.fill(privateKeyBytes, (byte) 0x00);
            }

            if (dsaKeyId != 0) {
                this.nativeImpl.DSAKEY_delete(dsaKeyId);
                dsaKeyId = 0;
            }

            if (pkeyId != 0) {
                this.nativeImpl.PKEY_delete(pkeyId);
                pkeyId = 0;
            }
        } finally {
            super.finalize();
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "Id :"+ id);
        return (id != 0L);
    }
}
