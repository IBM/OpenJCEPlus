/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.util.Arrays;

public final class DHKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private boolean isFIPS;
    private long dhKeyId = 0;
    private long pkeyId = 0;

    private byte[] privateKeyBytes = null;
    private byte[] publicKeyBytes = null;
    private byte[] parameters = null;
    private final String badIdMsg = "DH Key Identifier is not valid";
    private static final String badIdMsg1 = "Public or Private Key Identifier is not valid";
    private static final String debPrefix = "DHKey";

    public static DHKey generateKeyPair(boolean isFIPS, byte[] parameters)
            throws OCKException {
        //final String methodName = "generateKeyPair(byte[]) ";

        if (parameters == null || parameters.length == 0) {
            throw new IllegalArgumentException("DH parameters are null/empty");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dhKeyId = nativeImpl.DHKEY_generate(parameters);
        return new DHKey(isFIPS, dhKeyId, parameters.clone(), unobtainedKeyBytes,
                unobtainedKeyBytes);
    }

    public static DHKey generateKeyPair(boolean isFIPS, int numBits) throws OCKException {
        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dhKeyId = nativeImpl.DHKEY_generate(numBits);
        return new DHKey(isFIPS, dhKeyId, null, unobtainedKeyBytes, unobtainedKeyBytes);
    }

    public static byte[] generateParameters(boolean isFIPS, int numBits) {
        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        return nativeImpl.DHKEY_generateParameters(numBits);
    }

    public static DHKey createPrivateKey(boolean isFIPS, byte[] privateKeyBytes)
            throws OCKException {
        //final String methodName = "DHKey createPrivateKey (byte[]) ";
        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dhKeyId = nativeImpl.DHKEY_createPrivateKey(privateKeyBytes);
        return new DHKey(isFIPS, dhKeyId, null, privateKeyBytes.clone(), null);
    }

    public static DHKey createPublicKey(boolean isFIPS, byte[] publicKeyBytes)
            throws OCKException {
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long dhKeyId = nativeImpl.DHKEY_createPublicKey(publicKeyBytes);
        return new DHKey(isFIPS, dhKeyId, null, null, publicKeyBytes.clone());
    }

    private DHKey(boolean isFIPS, long dhKeyId, byte[] parameters, byte[] privateKeyBytes,
            byte[] publicKeyBytes) {
        this.isFIPS = isFIPS;
        this.dhKeyId = dhKeyId;
        this.pkeyId = 0;
        this.parameters = parameters;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
    }

    @Override
    public String getAlgorithm() {
        return "DH";
    }

    public long getDHKeyId() {
        //final String methodName = "getDHKeyId() :";
        //OCKDebug.Msg(debPrefix, methodName, this.dhKeyId);
        return this.dhKeyId;
    }

    @Override
    public long getPKeyId() throws OCKException {
        //final String methodName = "getPKeyId() :";
        if (pkeyId == 0) {
            obtainPKeyId();
        }
        return pkeyId;
    }

    @Override
    public byte[] getPrivateKeyBytes() throws OCKException {
        //final String methodName = "getPrivateKeyBytes () :";
        if (privateKeyBytes == unobtainedKeyBytes) {
            obtainPrivateKeyBytes();
        }

        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    public byte[] getParameters() throws OCKException {
        //final String methodName = "getParameters () :";
        if (parameters == null) {
            obtainParameters();
        }
        return (parameters == null) ? null : parameters.clone();
    }

    @Override
    public byte[] getPublicKeyBytes() throws OCKException {
        //final String methodName = "getPublicKeyBytes () :";
        if (publicKeyBytes == unobtainedKeyBytes) {
            obtainPublicKeyBytes();
        }
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    // There is a double lock on pubKeyId and privKeyId to ensure that the underlying native
    // pointers are not concurrently used by another DH operation. This is needed as the method
    // DHKey.computeDHSecret is not synchronized and not thread safe.
    // The method DHKey.computeDHSecret should NOT be synchronized for performance as that would create a global lock.
    public static byte[] computeDHSecret(boolean isFIPS, long pubKeyId, long privKeyId)
            throws OCKException {
        //final String methodName = "computeDHSecret";
        if (pubKeyId == 0) {
            throw new IllegalArgumentException("The public key parameter is not valid");
        }

        if (privKeyId == 0) {
            throw new IllegalArgumentException("The private key parameter is not valid");
        }


        if (!validId(pubKeyId) || !validId(privKeyId)) {
            throw new OCKException(badIdMsg1);
        }
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        byte[] sharedSecretBytes = nativeImpl.DHKEY_computeDHSecret(pubKeyId, privKeyId);
        return sharedSecretBytes;
    }

    private synchronized void obtainPKeyId() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPKeyId at the same time, we only want to call the native
        // code one time.
        if (pkeyId == 0) {
            if (!validId(dhKeyId)) {
                throw new OCKException(badIdMsg);
            }
            NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
            this.pkeyId = nativeImpl.DHKEY_createPKey(dhKeyId);
        }
    }

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        if (privateKeyBytes == unobtainedKeyBytes) {
            if (!validId(dhKeyId)) {
                throw new OCKException(badIdMsg);
            }
            NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
            this.privateKeyBytes = nativeImpl.DHKEY_getPrivateKeyBytes(dhKeyId);
        }
    }

    private synchronized void obtainPublicKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        if (publicKeyBytes == unobtainedKeyBytes) {
            NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
            this.publicKeyBytes = nativeImpl.DHKEY_getPublicKeyBytes(dhKeyId);
        }
    }

    private synchronized void obtainParameters() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getParameters at the same time, we only want to call the
        // native code one time.
        if (parameters == null) {
            if (!validId(dhKeyId)) {
                throw new OCKException(badIdMsg);
            }
            NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
            this.parameters = nativeImpl.DHKEY_getParameters(dhKeyId);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize";
        try {
            if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                Arrays.fill(privateKeyBytes, (byte) 0x00);
            }

            NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
            if (dhKeyId != 0) {
                nativeImpl.DHKEY_delete(dhKeyId);
                dhKeyId = 0;
            }

            if (pkeyId != 0) {
                nativeImpl.PKEY_delete(pkeyId);
                pkeyId = 0;
            }
        } finally {
            super.finalize();
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        // OCKDebug.Msg (debPrefix, methodName, "Id :" + id);
        return (id != 0L);
    }
}
