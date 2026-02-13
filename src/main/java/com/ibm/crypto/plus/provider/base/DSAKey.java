/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.PrimitiveWrapper;
import java.util.Arrays;

public final class DSAKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OpenJCEPlusProvider provider;
    private OCKContext ockContext;
    private final long dsaKeyId;
    private PrimitiveWrapper.Long pkeyId;
    private byte[] parameters;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private static final String badIdMsg = "DSA Key Identifier is not valid";
    private final static String debPrefix = "DSAKey";

    public static DSAKey generateKeyPair(OCKContext ockContext, int numBits, OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "generateKeyPair(numBits) ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        long dsaKeyId = NativeInterface.DSAKEY_generate(ockContext.getId(), numBits);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        //OCKDebug.Msg (debPrefix, methodName, "dsaKeyId=" + dsaKeyId);
        return new DSAKey(ockContext, dsaKeyId, null, unobtainedKeyBytes, unobtainedKeyBytes, provider);
    }

    public static byte[] generateParameters(OCKContext ockContext, int numBits)
            throws OCKException {
        //final String methodName = "generateParameters(numBits) ";
        byte[] paramBytes = null;
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }
        //OCKDebug.Msg (debPrefix, methodName, "numBits=" + numBits);
        paramBytes = NativeInterface.DSAKEY_generateParameters(ockContext.getId(), numBits);
        if (paramBytes == null) {
            throw new OCKException("The generated DSA parameter bytes are incorrect.");
        }
        return paramBytes;
    }

    public static DSAKey generateKeyPair(OCKContext ockContext, byte[] parameters, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "generateKeyPair";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (parameters == null || parameters.length == 0) {
            throw new IllegalArgumentException("DSA parameters are null/empty");
        }

        long dsaKeyId = NativeInterface.DSAKEY_generate(ockContext.getId(), parameters);
        //OCKDebug.Msg (debPrefix, methodName, "dsaKeyId=" + dsaKeyId);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        return new DSAKey(ockContext, dsaKeyId, parameters.clone(), unobtainedKeyBytes,
                unobtainedKeyBytes, provider);
    }

    public static DSAKey createPrivateKey(OCKContext ockContext, byte[] privateKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "createPrivateKey ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        long dsaKeyId = NativeInterface.DSAKEY_createPrivateKey(ockContext.getId(),
                privateKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "dsakKeyId=" + dsaKeyId);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        return new DSAKey(ockContext, dsaKeyId, null, privateKeyBytes.clone(), null, provider);
    }

    public static DSAKey createPublicKey(OCKContext ockContext, byte[] publicKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "createPublicKey";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        long dsaKeyId = NativeInterface.DSAKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
        if (!validId(dsaKeyId)) {
            throw new OCKException(badIdMsg);
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        //OCKDebug.Msg (debPrefix, methodName, "dsakKeyId=" + dsaKeyId);
        return new DSAKey(ockContext, dsaKeyId, null, null, publicKeyBytes.clone(), provider);
    }

    private DSAKey(OCKContext ockContext, long dsaKeyId, byte[] parameters, byte[] privateKeyBytes,
            byte[] publicKeyBytes, OpenJCEPlusProvider provider) {
        this.ockContext = ockContext;
        this.dsaKeyId = dsaKeyId;
        this.pkeyId = new PrimitiveWrapper.Long(0);
        this.parameters = parameters;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
        this.provider = provider;

        this.provider.registerCleanable(this, cleanOCKResources(privateKeyBytes, dsaKeyId, pkeyId, ockContext));
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
        if (pkeyId.getValue() == 0) {
            obtainPKeyId();
        }
        //OCKDebug.Msg (debPrefix, methodName, pkeyId);
        return pkeyId.getValue();
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
        if (pkeyId.getValue() == 0) {
            if (!validId(dsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.pkeyId.setValue(NativeInterface.DSAKEY_createPKey(ockContext.getId(), dsaKeyId));
            if (!validId(pkeyId.getValue())) {
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
            this.parameters = NativeInterface.DSAKEY_getParameters(ockContext.getId(), dsaKeyId);
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
            this.privateKeyBytes = NativeInterface.DSAKEY_getPrivateKeyBytes(ockContext.getId(),
                    dsaKeyId);
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
            this.publicKeyBytes = NativeInterface.DSAKEY_getPublicKeyBytes(ockContext.getId(),
                    dsaKeyId);
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "Id :"+ id);
        return (id != 0L);
    }

    private Runnable cleanOCKResources(byte[] privateKeyBytes, long dsaKeyId, PrimitiveWrapper.Long pkeyId, OCKContext ockContext) {
        return () -> {
            try {
                if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                    Arrays.fill(privateKeyBytes, (byte) 0x00);
                }
                if (dsaKeyId != 0) {
                    NativeInterface.DSAKEY_delete(ockContext.getId(), dsaKeyId);
                }
                if (pkeyId.getValue() != 0) {
                    NativeInterface.PKEY_delete(ockContext.getId(), pkeyId.getValue());
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
