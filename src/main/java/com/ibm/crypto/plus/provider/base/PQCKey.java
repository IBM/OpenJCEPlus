/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.util.Arrays;

public final class PQCKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private boolean isFIPS;
    private NativeInterface nativeImpl = null;
    private long pkeyId;
    private String algName;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private final static String badIdMsg = "Key Identifier is not valid";

    public static PQCKey generateKeyPair(boolean isFIPS, String algName)
            throws OCKException {
        long keyId = 0;
        // final String methodName = "generateKeyPair ";
        try {
            String NoDashAlg = algName.replace('-', '_');
            NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
            keyId = nativeImpl.MLKEY_generate(NoDashAlg);

            if (keyId == 0) {
                throw new OCKException("PQCKey.generateKeyPair: MLKEY_generate failed");
            }
        } catch (Exception e) {
            throw new OCKException("PQCKey.generateKeyPair: Exception " + e.getMessage(), e);
        }
        return new PQCKey(isFIPS, keyId, unobtainedKeyBytes, unobtainedKeyBytes, algName);
    }

    public static PQCKey createPrivateKey(boolean isFIPS, String algName, byte[] privateKeyBytes)
            throws OCKException {
        // final String methodName = "createPrivateKey ";

        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        long keyId = 0;
        String NoDashAlg = algName.replace('-', '_');
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        keyId = nativeImpl.MLKEY_createPrivateKey( NoDashAlg, privateKeyBytes);

        return new PQCKey(isFIPS, keyId, privateKeyBytes.clone(), null, algName);
    }

    public static PQCKey createPublicKey(boolean isFIPS,  String algName, byte[] publicKeyBytes)
            throws OCKException {
        // final String methodName = "createPublicKey ";

        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        long keyId = 0;
        String NoDashAlg = algName.replace('-', '_');
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        keyId = nativeImpl.MLKEY_createPublicKey(NoDashAlg, publicKeyBytes);

        // OCKDebug.Msg (debPrefix, methodName, "mlkemKeyId :" + mlkemKeyId);
        return new PQCKey(isFIPS, keyId, null, publicKeyBytes.clone(), algName);
    }

    private PQCKey(boolean isFIPS, long keyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes, String algName) throws OCKException {
        this.isFIPS = isFIPS;
        this.nativeImpl = NativeInterfaceFactory.getImpl(this.isFIPS);
        this.pkeyId = keyId;
        this.algName = algName;

        if (!validId(pkeyId)) {
            throw new OCKException(badIdMsg);
        }

        if (privateKeyBytes == unobtainedKeyBytes) {
            this.privateKeyBytes = nativeImpl.MLKEY_getPrivateKeyBytes(keyId);
        } else {
            this.privateKeyBytes = privateKeyBytes;
        }
        if (publicKeyBytes == unobtainedKeyBytes) {
            this.publicKeyBytes = nativeImpl.MLKEY_getPublicKeyBytes(keyId);
        } else {
            this.publicKeyBytes = publicKeyBytes;
        }
    }

    @Override
    public String getAlgorithm() {
        return algName;
    }

    @Override
    public long getPKeyId() throws OCKException {
        return pkeyId;
    }

    @Override
    public byte[] getPrivateKeyBytes() throws OCKException {
        // final String methodName = "getPrivateKeyBytes :";
        if (privateKeyBytes == unobtainedKeyBytes) {
            obtainPrivateKeyBytes();
        }
        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    @Override
    public byte[] getPublicKeyBytes() throws OCKException {
        // final String methodName = "getPublicKeyBytes";
        if (publicKeyBytes == unobtainedKeyBytes) {
            obtainPublicKeyBytes();
        }
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (privateKeyBytes == unobtainedKeyBytes) {
            if (!validId(pkeyId)) {
                throw new OCKException(badIdMsg);
            }
        
            System.out.println("getPrivKeyBytes - pkeyId :" + pkeyId);
            this.privateKeyBytes = nativeImpl.MLKEY_getPrivateKeyBytes(pkeyId);
        }
    }

    private synchronized void obtainPublicKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (publicKeyBytes == unobtainedKeyBytes) {
            if (!validId(pkeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.publicKeyBytes = nativeImpl.MLKEY_getPublicKeyBytes(pkeyId);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        // final String methodName = "finalize ";
        // OCKDebug.Msg(debPrefix, methodName, " pkeyId=" +
        // pkeyId);
        try {
            if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                Arrays.fill(privateKeyBytes, (byte) 0x00);
            }

            if (pkeyId != 0) {
                nativeImpl.MLKEY_delete(pkeyId);
                pkeyId = 0;
            }
        } finally {
            super.finalize();
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        // final String methodName = "validId";
        // OCKDebug.Msg(debPrefix, methodName, id);
        return (id != 0L);
    }
    public String toString() {
        String out = "Algorithm Name =  " + this.algName + "\n" +
            "Private Key - " + this.privateKeyBytes + "\n" +
            "Public Key - " + this.publicKeyBytes;
        return out;
    }
}
