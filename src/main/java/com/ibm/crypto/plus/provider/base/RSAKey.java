/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.math.BigInteger;
import java.util.Arrays;

public final class RSAKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private boolean isFIPS;
    private NativeInterface nativeImpl = null;
    private long rsaKeyId;
    private long pkeyId;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private int keySize;
    private final static String badIdMsg = "RSA Key Identifier is not valid";
    private final static String debPrefix = "RSAKey";

    public static RSAKey generateKeyPair(boolean isFIPS, int numBits, BigInteger e)
            throws OCKException {
        //final String methodName = "generateKeyPair ";

        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long rsaKeyId = nativeImpl.RSAKEY_generate(numBits, e.longValue());
        //OCKDebug.Msg (debPrefix, methodName,  "numBits=" + numBits + " rsaKeyId=" + rsaKeyId);
        return new RSAKey(isFIPS, rsaKeyId, unobtainedKeyBytes, unobtainedKeyBytes);
    }

    public static RSAKey createPrivateKey(boolean isFIPS, byte[] privateKeyBytes)
            throws OCKException {
        //final String methodName = "createPrivateKey ";
        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long rsaKeyId = nativeImpl.RSAKEY_createPrivateKey(privateKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "rsaKeyId :" + rsaKeyId);
        return new RSAKey(isFIPS, rsaKeyId, privateKeyBytes.clone(), null);
    }

    public static RSAKey createPublicKey(boolean isFIPS, byte[] publicKeyBytes)
            throws OCKException {
        //final String methodName = "createPublicKey ";
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long rsaKeyId = nativeImpl.RSAKEY_createPublicKey(publicKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "rsaKeyId :" + rsaKeyId);
        return new RSAKey(isFIPS, rsaKeyId, null, publicKeyBytes.clone());
    }

    private RSAKey(boolean isFIPS, long rsaKeyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes) {
        this.isFIPS = isFIPS;
        this.nativeImpl = NativeInterfaceFactory.getImpl(this.isFIPS);
        this.rsaKeyId = rsaKeyId;
        this.pkeyId = 0;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
        this.keySize = 0;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    public long getRSAKeyId() {
        return this.rsaKeyId;
    }

    @Override
    public long getPKeyId() throws OCKException {
        //final String methodName = "getPkeyId :";
        if (pkeyId == 0) {
            obtainPKeyId();
        }
        //OCKDebug.Msg(debPrefix, methodName,   this.pkeyId);
        return pkeyId;
    }

    public int getKeySize() throws OCKException {
        //final String methodName = "getKeySize";
        if (keySize == 0) {
            obtainKeySize();
        }
        //OCKDebug.Msg (debPrefix, methodName, keySize);
        return keySize;
    }

    @Override
    public byte[] getPrivateKeyBytes() throws OCKException {
        //final String methodName = "getPrivateKeyBytes :";
        if (privateKeyBytes == unobtainedKeyBytes) {
            obtainPrivateKeyBytes();
        }
        //OCKDebug.Msg(debPrefix, methodName,  privateKeyBytes);
        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    @Override
    public byte[] getPublicKeyBytes() throws OCKException {
        //final String methodName = "getPrivateKeyBytes";
        if (publicKeyBytes == unobtainedKeyBytes) {
            obtainPublicKeyBytes();
        }
        //OCKDebug.Msg(debPrefix, methodName, publicKeyBytes);
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    private synchronized void obtainPKeyId() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPKeyId at the same time, we only want to call the native
        // code one time.
        //
        if (pkeyId == 0) {
            if (!validId(rsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.pkeyId = this.nativeImpl.RSAKEY_createPKey(rsaKeyId);
        }
    }

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (privateKeyBytes == unobtainedKeyBytes) {
            if (!validId(rsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.privateKeyBytes = this.nativeImpl.RSAKEY_getPrivateKeyBytes(rsaKeyId);
        }
    }

    private synchronized void obtainPublicKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (publicKeyBytes == unobtainedKeyBytes) {
            if (!validId(rsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.publicKeyBytes = this.nativeImpl.RSAKEY_getPublicKeyBytes(rsaKeyId);
        }
    }

    private synchronized void obtainKeySize() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to obtainKeySize at the same time, we only want to call the
        // native code one time.
        //
        if (this.keySize == 0) {
            if (!validId(rsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.keySize = this.nativeImpl.RSAKEY_size(rsaKeyId);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize ";
        //OCKDebug.Msg(debPrefix, methodName, "rsaKeyId=" + rsaKeyId + " pkeyId=" + pkeyId);
        try {
            if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                Arrays.fill(privateKeyBytes, (byte) 0x00);
            }

            if (rsaKeyId != 0) {
                this.nativeImpl.RSAKEY_delete(rsaKeyId);
                rsaKeyId = 0;
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
        //OCKDebug.Msg(debPrefix, methodName, id);
        return (id != 0L);
    }

}
