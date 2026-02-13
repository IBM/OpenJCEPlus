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
import java.math.BigInteger;
import java.util.Arrays;

public final class RSAKey implements AsymmetricKey {

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final long rsaKeyId;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private int keySize;
    private final static String badIdMsg = "RSA Key Identifier is not valid";
    private final static String debPrefix = "RSAKey";

    public static RSAKey generateKeyPair(int numBits, BigInteger e, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "generateKeyPair ";
        if (numBits < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long rsaKeyId = nativeInterface.RSAKEY_generate(numBits, e.longValue());
        //OCKDebug.Msg (debPrefix, methodName,  "numBits=" + numBits + " rsaKeyId=" + rsaKeyId);
        return new RSAKey(nativeInterface, rsaKeyId, unobtainedKeyBytes, unobtainedKeyBytes, provider);
    }

    public static RSAKey createPrivateKey(byte[] privateKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "createPrivateKey ";
        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long rsaKeyId = nativeInterface.RSAKEY_createPrivateKey(privateKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "rsaKeyId :" + rsaKeyId);
        return new RSAKey(nativeInterface, rsaKeyId, privateKeyBytes.clone(), null, provider);
    }

    public static RSAKey createPublicKey(byte[] publicKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "createPublicKey ";
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long rsaKeyId = nativeInterface.RSAKEY_createPublicKey(publicKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "rsaKeyId :" + rsaKeyId);
        return new RSAKey(nativeInterface, rsaKeyId, null, publicKeyBytes.clone(), provider);
    }

    private RSAKey(NativeInterface nativeInterface, long rsaKeyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes, OpenJCEPlusProvider provider) {
        this.rsaKeyId = rsaKeyId;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
        this.keySize = 0;
        this.provider = provider;
        this.nativeInterface = nativeInterface;

        this.provider.registerCleanable(this, cleanOCKResources(privateKeyBytes, rsaKeyId, nativeInterface));
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
        return this.rsaKeyId;
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

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (privateKeyBytes == unobtainedKeyBytes) {
            if (!validId(rsaKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.privateKeyBytes = this.nativeInterface.RSAKEY_getPrivateKeyBytes(rsaKeyId);
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
            this.publicKeyBytes = this.nativeInterface.RSAKEY_getPublicKeyBytes(rsaKeyId);
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
            this.keySize = this.nativeInterface.RSAKEY_size(rsaKeyId);
        }
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg(debPrefix, methodName, id);
        return (id != 0L);
    }

    private Runnable cleanOCKResources(byte[] privateKeyBytes, long rsaKeyId, NativeInterface nativeInterface) {
        return () -> {
            try {
                if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                    Arrays.fill(privateKeyBytes, (byte) 0x00);
                }
                if (rsaKeyId != 0) {
                    nativeInterface.RSAKEY_delete(rsaKeyId);
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
