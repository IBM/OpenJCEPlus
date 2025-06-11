/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.util.Arrays;

public final class PQCKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OCKContext ockContext;
    private long pkeyId;
    private String algName; 
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private final static String badIdMsg = "Key Identifier is not valid";

    public static PQCKey generateKeyPair(OCKContext ockContext, String algName)
            throws OCKException {
        long keyId = 0;        
        // final String methodName = "generateKeyPair ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }
        try {
            String NoDashAlg = algName.replace('-','_');
            keyId = NativeInterface.MLKEY_generate(ockContext.getId(), NoDashAlg);

            if (keyId == 0) {   
                throw new OCKException("OCKPQCKey.generateKeyPair: MLKEY_generate failed");
            }    
        } catch (Exception e) {
            throw new OCKException("OCKPQCKey.generateKeyPair: Exception " + e.getCause());
        }
        return new PQCKey(ockContext, keyId, unobtainedKeyBytes, unobtainedKeyBytes, algName);
    }

    public static PQCKey createPrivateKey(OCKContext ockContext, String algName, byte[] privateKeyBytes)
            throws OCKException {
        // final String methodName = "createPrivateKey ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        long keyId = 0;
        String NoDashAlg = algName.replace('-','_');
        keyId = NativeInterface.MLKEY_createPrivateKey(ockContext.getId(), NoDashAlg,
                privateKeyBytes);

        return new PQCKey(ockContext, keyId, privateKeyBytes.clone(), null, algName);
    }

    public static PQCKey createPublicKey(OCKContext ockContext,  String algName, byte[] publicKeyBytes)
            throws OCKException {
        // final String methodName = "createPublicKey ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        long keyId = 0;
        String NoDashAlg = algName.replace('-','_');
        keyId = NativeInterface.MLKEY_createPublicKey(ockContext.getId(), NoDashAlg,
            publicKeyBytes);

        // OCKDebug.Msg (debPrefix, methodName, "mlkemKeyId :" + mlkemKeyId);
        return new PQCKey(ockContext, keyId, null, publicKeyBytes.clone(), algName);
    }

    private PQCKey(OCKContext ockContext, long keyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes, String algName) throws OCKException {
        this.ockContext = ockContext;
        this.pkeyId = keyId;
        this.algName = algName;

        if (!validId(pkeyId)) {
            throw new OCKException(badIdMsg);
        }

        if (privateKeyBytes == unobtainedKeyBytes) {
            this.privateKeyBytes = NativeInterface.MLKEY_getPrivateKeyBytes(ockContext.getId(),
            keyId);
        } else {
            this.privateKeyBytes = privateKeyBytes;
        }
        if (publicKeyBytes == unobtainedKeyBytes) {
            this.publicKeyBytes = NativeInterface.MLKEY_getPublicKeyBytes(ockContext.getId(),
            keyId);
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
            this.privateKeyBytes = NativeInterface.MLKEY_getPrivateKeyBytes(ockContext.getId(),
            pkeyId);
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
            this.publicKeyBytes = NativeInterface.MLKEY_getPublicKeyBytes(ockContext.getId(),
            pkeyId);
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
                NativeInterface.MLKEY_delete(ockContext.getId(), pkeyId);
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
