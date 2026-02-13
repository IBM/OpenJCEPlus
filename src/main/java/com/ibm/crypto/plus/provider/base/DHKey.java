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
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;
import java.util.Arrays;

public final class DHKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final long dhKeyId;
    private PrimitiveWrapper.Long pkeyId = new PrimitiveWrapper.Long(0);

    private byte[] privateKeyBytes = null;
    private byte[] publicKeyBytes = null;
    private byte[] parameters = null;
    private final String badIdMsg = "DH Key Identifier is not valid";
    private static final String badIdMsg1 = "Public or Private Key Identifier is not valid";
    private static final String debPrefix = "DHKey";

    public static DHKey generateKeyPair(byte[] parameters, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "generateKeyPair(byte[]) ";

        if (parameters == null || parameters.length == 0) {
            throw new IllegalArgumentException("DH parameters are null/empty");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long dhKeyId = nativeInterface.DHKEY_generate(parameters);
        return new DHKey(nativeInterface, dhKeyId, parameters.clone(), unobtainedKeyBytes,
                unobtainedKeyBytes, provider);
    }

    public static DHKey generateKeyPair(int numBits, OpenJCEPlusProvider provider) throws OCKException {
        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long dhKeyId = nativeInterface.DHKEY_generate(numBits);
        return new DHKey(nativeInterface, dhKeyId, null, unobtainedKeyBytes, unobtainedKeyBytes, provider);
    }

    public static byte[] generateParameters(OpenJCEPlusProvider provider, int numBits) {
        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }
        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        return nativeInterface.DHKEY_generateParameters(numBits);
    }

    public static DHKey createPrivateKey(byte[] privateKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "DHKey createPrivateKey (byte[]) ";
        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long dhKeyId = nativeInterface.DHKEY_createPrivateKey(privateKeyBytes);
        return new DHKey(nativeInterface, dhKeyId, null, privateKeyBytes.clone(), null, provider);
    }

    public static DHKey createPublicKey(byte[] publicKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long dhKeyId = nativeInterface.DHKEY_createPublicKey(publicKeyBytes);
        return new DHKey(nativeInterface, dhKeyId, null, null, publicKeyBytes.clone(), provider);
    }

    private DHKey(NativeInterface nativeInterface, long dhKeyId, byte[] parameters, byte[] privateKeyBytes,
            byte[] publicKeyBytes, OpenJCEPlusProvider provider) {
        this.nativeInterface = nativeInterface;
        this.dhKeyId = dhKeyId;
        this.pkeyId.setValue(0);
        this.parameters = parameters;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
        this.provider = provider;

        this.provider.registerCleanable(this, cleanOCKResources(privateKeyBytes, dhKeyId, pkeyId, nativeInterface));
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
        if (pkeyId.getValue() == 0) {
            obtainPKeyId();
        }
        return pkeyId.getValue();
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
    public static byte[] computeDHSecret(NativeInterface nativeInterface, long pubKeyId, long privKeyId)
            throws OCKException {
        //final String methodName = "computeDHSecret";
        if (nativeInterface == null) {
            throw new IllegalArgumentException("nativeInterface is null");
        }

        if (pubKeyId == 0) {
            throw new IllegalArgumentException("The public key parameter is not valid");
        }

        if (privKeyId == 0) {
            throw new IllegalArgumentException("The private key parameter is not valid");
        }

        if (!validId(pubKeyId) || !validId(privKeyId)) {
            throw new OCKException(badIdMsg1);
        }
        byte[] sharedSecretBytes = nativeInterface.DHKEY_computeDHSecret(pubKeyId, privKeyId);
        return sharedSecretBytes;
    }

    private synchronized void obtainPKeyId() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPKeyId at the same time, we only want to call the native
        // code one time.
        if (pkeyId.getValue() == 0) {
            if (!validId(dhKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.pkeyId.setValue(this.nativeInterface.DHKEY_createPKey(dhKeyId));
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
            this.privateKeyBytes = this.nativeInterface.DHKEY_getPrivateKeyBytes(dhKeyId);
        }
    }

    private synchronized void obtainPublicKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        if (publicKeyBytes == unobtainedKeyBytes) {
            this.publicKeyBytes = this.nativeInterface.DHKEY_getPublicKeyBytes(dhKeyId);
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
            this.parameters = this.nativeInterface.DHKEY_getParameters(dhKeyId);
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        // OCKDebug.Msg (debPrefix, methodName, "Id :" + id);
        return (id != 0L);
    }



    private Runnable cleanOCKResources(byte[] privateKeyBytes, long dhKeyId, PrimitiveWrapper.Long pkeyId, NativeInterface nativeInterface) {
        return () -> {
            try {
                if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                    Arrays.fill(privateKeyBytes, (byte) 0x00);
                }
                if (dhKeyId != 0) {
                    nativeInterface.DHKEY_delete(dhKeyId);
                }
                if (pkeyId.getValue() != 0) {
                    nativeInterface.PKEY_delete(pkeyId.getValue());
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
