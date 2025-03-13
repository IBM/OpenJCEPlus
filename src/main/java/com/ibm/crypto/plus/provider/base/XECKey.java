/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.util.Arrays;

public final class XECKey implements AsymmetricKey {
    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];
    private boolean isFIPS;
    private NativeInterface nativeImpl = null;
    private long xecKeyId;
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

    private XECKey(boolean isFIPS, long xecKeyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes) {
        //final String methodName = "XECKey(long, byte[], byte[]) ";
        this.isFIPS = isFIPS;
        this.nativeImpl = NativeInterfaceFactory.getImpl(this.isFIPS);
        this.xecKeyId = xecKeyId;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
    }


    public static XECKey generateKeyPair(boolean isFIPS, int curveNum, int pub_size)
            throws OCKException {
        //final String methodName = "generateKeyPair(NamedParameterSpec.CURVE) ";
        FastJNIBuffer buffer = XECKey.buffer.get();

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long xecKeyId = nativeImpl.XECKEY_generate(curveNum,
                buffer.pointer());
        if (!validId(xecKeyId))
            throw new OCKException(badIdMsg);

        byte[] publicKeyBytes = new byte[pub_size];
        buffer.get(0, publicKeyBytes, 0, pub_size);

        return new XECKey(isFIPS, xecKeyId, unobtainedKeyBytes, publicKeyBytes);
    }

    public static byte[] computeECDHSecret(boolean isFIPS, long genCtx, long pubId,
            long privId, int secrectBufferSize) throws OCKException {
        if (pubId == 0)
            throw new IllegalArgumentException("The public key parameter is not valid");
        if (privId == 0)
            throw new IllegalArgumentException("The private key parameter is not valid");

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        byte[] sharedSecretBytes = nativeImpl.XECKEY_computeECDHSecret(
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
            this.privateKeyBytes = this.nativeImpl.XECKEY_getPrivateKeyBytes(xecKeyId); // Returns DER encoded bytes
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

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize ";
        //OCKDebug.Msg(debPrefix, methodName,  "ecKeyId :" + ecKeyId + " pkeyId=" + pkeyId);
        try {
            if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                Arrays.fill(privateKeyBytes, (byte) 0x00);
            }

            if (xecKeyId != 0) {
                this.nativeImpl.XECKEY_delete(xecKeyId);
                xecKeyId = 0;
            }
        } finally {
            super.finalize();
        }
    }

    public synchronized static XECKey createPrivateKey(boolean isFIPS,
            byte[] privateKeyBytes, int priv_size) throws OCKException {
        //final String methodName = "createPrivateKey";
        if (privateKeyBytes == null)
            throw new IllegalArgumentException("key bytes is null");

        FastJNIBuffer buffer = XECKey.buffer.get();

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long xecKeyId = nativeImpl.XECKEY_createPrivateKey(privateKeyBytes,
                buffer.pointer());
        if (!validId(xecKeyId))
            throw new OCKException(badIdMsg);

        // buffer now contains public key
        byte[] publicKeyBytes = new byte[priv_size];
        buffer.get(0, publicKeyBytes, 0, priv_size);

        return new XECKey(isFIPS, xecKeyId, privateKeyBytes.clone(), publicKeyBytes);
    }

    public static XECKey createPublicKey(boolean isFIPS, byte[] publicKeyBytes)
            throws OCKException {
        //final String methodName = "createPublicKey";
        if (publicKeyBytes == null)
            throw new IllegalArgumentException("key bytes is null");

        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        long xecKeyId = nativeImpl.XECKEY_createPublicKey(publicKeyBytes);
        return new XECKey(isFIPS, xecKeyId, null, publicKeyBytes.clone());
    }

    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public long getPKeyId() throws OCKException {
        return xecKeyId;
    }
}
