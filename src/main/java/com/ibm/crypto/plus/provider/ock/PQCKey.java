/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.util.Arrays;

public final class PQCKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OpenJCEPlusProvider provider;
    private OCKContext ockContext;
    private final long pkeyId;
    private String algName; 
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private final static String badIdMsg = "Key Identifier is not valid";

    public static PQCKey generateKeyPair(OCKContext ockContext, String algName, OpenJCEPlusProvider provider)
            throws OCKException {
        long keyId = 0;
        // final String methodName = "generateKeyPair ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        try {
            String NoDashAlg = algName.replace('-', '_');
            keyId = NativeInterface.MLKEY_generate(ockContext.getId(), NoDashAlg);

            if (keyId == 0) {   
                throw new OCKException("PQCKey.generateKeyPair: MLKEY_generate failed");
            }    
        } catch (Exception e) {
            throw new OCKException("PQCKey.generateKeyPair: Exception " + e.getMessage(), e);
        }
        return new PQCKey(ockContext, keyId, unobtainedKeyBytes, unobtainedKeyBytes, algName, provider);
    }

    public static PQCKey createPrivateKey(OCKContext ockContext, String algName, byte[] privateKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        // final String methodName = "createPrivateKey ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        long keyId = 0;
        String NoDashAlg = algName.replace('-', '_');
        keyId = NativeInterface.MLKEY_createPrivateKey(ockContext.getId(), NoDashAlg,
                privateKeyBytes);

        return new PQCKey(ockContext, keyId, privateKeyBytes.clone(), null, algName, provider);
    }

    public static PQCKey createPublicKey(OCKContext ockContext,  String algName, byte[] publicKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        // final String methodName = "createPublicKey ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        long keyId = 0;
        String NoDashAlg = algName.replace('-', '_');
        keyId = NativeInterface.MLKEY_createPublicKey(ockContext.getId(), NoDashAlg,
            publicKeyBytes);

        // OCKDebug.Msg (debPrefix, methodName, "mlkemKeyId :" + mlkemKeyId);
        return new PQCKey(ockContext, keyId, null, publicKeyBytes.clone(), algName, provider);
    }

    private PQCKey(OCKContext ockContext, long keyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes, String algName, OpenJCEPlusProvider provider) throws OCKException {
        this.ockContext = ockContext;
        this.pkeyId = keyId;
        this.algName = algName;
        this.provider = provider;

        if (!validId(pkeyId)) {
            throw new OCKException(badIdMsg);
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
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

        this.provider.registerCleanable(this, cleanOCKResources(privateKeyBytes, pkeyId, ockContext));
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

    private Runnable cleanOCKResources(byte[] privateKeyBytes, long pkeyId, OCKContext ockContext){
        return() -> {
            try {
                if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                    Arrays.fill(privateKeyBytes, (byte) 0x00);
                }
                if (pkeyId != 0) {
                    NativeInterface.MLKEY_delete(ockContext.getId(), pkeyId);
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
