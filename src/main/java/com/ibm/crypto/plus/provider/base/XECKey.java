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
import java.util.Arrays;

public final class XECKey implements AsymmetricKey {
    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];
    private OpenJCEPlusProvider provider;
    private NativeInterface nativeInterface;
    private final long xecKeyId;
    private byte[] privateKeyBytes;
    private byte[] publicKeyBytes;
    private static final String badIdMsg = "XEC Key Identifier is not valid";
    private static final int FastJNIBufferSize = 3000;

    // Buffer to pass XDH data from/to native efficiently
    private static final ThreadLocal<FastJNIBuffer> buffer = new ThreadLocal<FastJNIBuffer>() {
        @Override
        protected FastJNIBuffer initialValue() {
            return FastJNIBuffer.create(FastJNIBufferSize);
        }
    };

    private XECKey(NativeInterface nativeInterface, long xecKeyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes, OpenJCEPlusProvider provider) {
        //final String methodName = "XECKey(long, byte[], byte[]) ";
        this.xecKeyId = xecKeyId;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
        this.provider = provider;
        this.nativeInterface = nativeInterface;
        this.provider.registerCleanable(this, cleanOCKResources(privateKeyBytes, xecKeyId, nativeInterface));
    }


    public static XECKey generateKeyPair(int curveNum, int pub_size, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "generateKeyPair(NamedParameterSpec.CURVE) ";
        FastJNIBuffer buffer = XECKey.buffer.get();

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long xecKeyId = nativeInterface.XECKEY_generate(curveNum,
                buffer.pointer());
        if (!validId(xecKeyId))
            throw new OCKException(badIdMsg);

        byte[] publicKeyBytes = new byte[pub_size];
        buffer.get(0, publicKeyBytes, 0, pub_size);

        return new XECKey(nativeInterface, xecKeyId, unobtainedKeyBytes, publicKeyBytes, provider);
    }

    public static byte[] computeECDHSecret(long genCtx, long pubId,
            long privId, int secrectBufferSize, OpenJCEPlusProvider provider) throws OCKException {
        if (pubId == 0)
            throw new IllegalArgumentException("The public key parameter is not valid");
        if (privId == 0)
            throw new IllegalArgumentException("The private key parameter is not valid");

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        byte[] sharedSecretBytes = nativeInterface.XECKEY_computeECDHSecret(
                genCtx, pubId, privId, secrectBufferSize);
        //OCKDebug.Msg (debPrefix, methodName,  "pubId :" + pubId + " privId :" + privId + " sharedSecretBytes :", sharedSecretBytes);
        return sharedSecretBytes;
    }

    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "id :" + id);
        return (id != 0L);
    }

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (privateKeyBytes == unobtainedKeyBytes) {
            if (!validId(xecKeyId))
                throw new OCKException(badIdMsg);
            this.privateKeyBytes = this.nativeInterface.XECKEY_getPrivateKeyBytes(xecKeyId); // Returns DER encoded bytes
        }
    }

    @Override
    public byte[] getPrivateKeyBytes() throws OCKException {
        //final String methodName = "getPrivateKeyBytes()";
        if (privateKeyBytes == unobtainedKeyBytes)
            obtainPrivateKeyBytes();
        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    @Override
    public byte[] getPublicKeyBytes() throws OCKException {
        //final String methodName = "getPublickeyBytes()";
        if (publicKeyBytes == unobtainedKeyBytes) {
            throw new OCKException(
                    "Public key should always be loaded on creation. Reaching this state means this object was initialized without a public key...");
        }
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    public synchronized static XECKey createPrivateKey(
            byte[] privateKeyBytes, int priv_size, OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "createPrivateKey";
        if (privateKeyBytes == null)
            throw new IllegalArgumentException("key bytes is null");
        if (provider == null) 
            throw new IllegalArgumentException("provider is null");

        FastJNIBuffer buffer = XECKey.buffer.get();

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long xecKeyId = nativeInterface.XECKEY_createPrivateKey(privateKeyBytes,
                buffer.pointer());
        if (!validId(xecKeyId))
            throw new OCKException(badIdMsg);

        // buffer now contains public key
        byte[] publicKeyBytes = new byte[priv_size];
        buffer.get(0, publicKeyBytes, 0, priv_size);

        return new XECKey(nativeInterface, xecKeyId, privateKeyBytes.clone(), publicKeyBytes, provider);
    }

    public static XECKey createPublicKey(byte[] publicKeyBytes, OpenJCEPlusProvider provider)
            throws OCKException {
        //final String methodName = "createPublicKey";
        if (publicKeyBytes == null)
            throw new IllegalArgumentException("key bytes is null");
        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        long xecKeyId = nativeInterface.XECKEY_createPublicKey(publicKeyBytes);
        return new XECKey(nativeInterface, xecKeyId, null, publicKeyBytes.clone(), provider);
    }

    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public long getPKeyId() throws OCKException {
        return xecKeyId;
    }

    private Runnable cleanOCKResources(byte[] privateKeyBytes, long xecKeyId, NativeInterface nativeInterface) {
        return () -> {
            try {
                if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                    Arrays.fill(privateKeyBytes, (byte) 0x00);
                }
                if (xecKeyId != 0) {
                    nativeInterface.XECKEY_delete(xecKeyId);
                }
            } catch (OCKException e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
