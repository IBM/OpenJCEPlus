/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.math.BigInteger;
import java.util.Arrays;

public final class RSAKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OCKContext ockContext;
    private long rsaKeyId;
    private long pkeyId;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private int keySize;
    private final static String badIdMsg = "RSA Key Identifier is not valid";
    private final static String debPrefix = "RSAKey";

    public static RSAKey generateKeyPair(OCKContext ockContext, int numBits, BigInteger e)
            throws OCKException {
        //final String methodName = "generateKeyPair ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        long rsaKeyId = NativeInterface.RSAKEY_generate(ockContext.getId(), numBits, e.longValue());
        //OCKDebug.Msg (debPrefix, methodName,  "numBits=" + numBits + " rsaKeyId=" + rsaKeyId);
        return new RSAKey(ockContext, rsaKeyId, unobtainedKeyBytes, unobtainedKeyBytes);
    }

    public static RSAKey createPrivateKey(OCKContext ockContext, byte[] privateKeyBytes)
            throws OCKException {
        //final String methodName = "createPrivateKey ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        long rsaKeyId = NativeInterface.RSAKEY_createPrivateKey(ockContext.getId(),
                privateKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "rsaKeyId :" + rsaKeyId);
        return new RSAKey(ockContext, rsaKeyId, privateKeyBytes.clone(), null);
    }

    public static RSAKey createPublicKey(OCKContext ockContext, byte[] publicKeyBytes)
            throws OCKException {
        //final String methodName = "createPublicKey ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        long rsaKeyId = NativeInterface.RSAKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "rsaKeyId :" + rsaKeyId);
        return new RSAKey(ockContext, rsaKeyId, null, publicKeyBytes.clone());
    }

    private RSAKey(OCKContext ockContext, long rsaKeyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes) {
        this.ockContext = ockContext;
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
            this.pkeyId = NativeInterface.RSAKEY_createPKey(ockContext.getId(), rsaKeyId);
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
            this.privateKeyBytes = NativeInterface.RSAKEY_getPrivateKeyBytes(ockContext.getId(),
                    rsaKeyId);
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
            this.publicKeyBytes = NativeInterface.RSAKEY_getPublicKeyBytes(ockContext.getId(),
                    rsaKeyId);
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
            this.keySize = NativeInterface.RSAKEY_size(ockContext.getId(), rsaKeyId);
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
                NativeInterface.RSAKEY_delete(ockContext.getId(), rsaKeyId);
                rsaKeyId = 0;
            }

            if (pkeyId != 0) {
                NativeInterface.PKEY_delete(ockContext.getId(), pkeyId);
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
