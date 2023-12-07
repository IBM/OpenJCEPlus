/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

import java.io.IOException;
import java.util.Arrays;
import ibm.security.internal.spec.NamedParameterSpec;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

public final class XECKey implements AsymmetricKey {
    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];
    private OCKContext ockContext;
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

    private XECKey(OCKContext ockContext, long xecKeyId, byte[] privateKeyBytes,
            byte[] publicKeyBytes) {
        //final String methodName = "XECKey(long, byte[], byte[]) ";
        this.ockContext = ockContext;
        this.xecKeyId = xecKeyId;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
    }


    public static XECKey generateKeyPair(OCKContext ockContext, NamedParameterSpec.CURVE curve)
            throws OCKException {
        //final String methodName = "generateKeyPair(NamedParameterSpec.CURVE) ";
        if (ockContext == null)
            throw new IllegalArgumentException("The context parameter is null");

        FastJNIBuffer buffer = XECKey.buffer.get();

        long xecKeyId = NativeInterface.XECKEY_generate(ockContext.getId(), curve.ordinal(),
                buffer.pointer());
        if (!validId(xecKeyId))
            throw new OCKException(badIdMsg);

        int pub_size = NamedParameterSpec.getPublicCurveSize(curve);
        byte[] publicKeyBytes = new byte[pub_size];
        buffer.get(0, publicKeyBytes, 0, pub_size);

        return new XECKey(ockContext, xecKeyId, unobtainedKeyBytes, publicKeyBytes);
    }

    public static byte[] computeECDHSecret(OCKContext ockContext, long genCtx, long pubId,
            long privId, int secrectBufferSize) throws OCKException {
        if (ockContext == null)
            throw new IllegalArgumentException("context is null");
        if (pubId == 0)
            throw new IllegalArgumentException("The public key parameter is not valid");
        if (privId == 0)
            throw new IllegalArgumentException("The private key parameter is not valid");

        byte[] sharedSecretBytes = NativeInterface.XECKEY_computeECDHSecret(ockContext.getId(),
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
            this.privateKeyBytes = NativeInterface.XECKEY_getPrivateKeyBytes(ockContext.getId(),
                    xecKeyId); // Returns DER encoded bytes
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
                NativeInterface.XECKEY_delete(ockContext.getId(), xecKeyId);
                xecKeyId = 0;
            }
        } finally {
            super.finalize();
        }
    }

    public synchronized static XECKey createPrivateKey(OCKContext ockContext,
            byte[] privateKeyBytes, NamedParameterSpec.CURVE curve) throws OCKException {
        //final String methodName = "createPrivateKey";
        if (ockContext == null)
            throw new IllegalArgumentException("context is null");
        if (privateKeyBytes == null)
            throw new IllegalArgumentException("key bytes is null");

        FastJNIBuffer buffer = XECKey.buffer.get();

        long xecKeyId = NativeInterface.XECKEY_createPrivateKey(ockContext.getId(), privateKeyBytes,
                buffer.pointer());
        if (!validId(xecKeyId))
            throw new OCKException(badIdMsg);

        // buffer now contains public key
        int priv_size = NamedParameterSpec.getPrivateCurveSize(curve);
        byte[] publicKeyBytes = new byte[priv_size];
        buffer.get(0, publicKeyBytes, 0, priv_size);

        return new XECKey(ockContext, xecKeyId, privateKeyBytes.clone(), publicKeyBytes);
    }

    public static XECKey createPublicKey(OCKContext ockContext, byte[] publicKeyBytes)
            throws OCKException {
        //final String methodName = "createPublicKey";
        if (ockContext == null)
            throw new IllegalArgumentException("context is null");
        if (publicKeyBytes == null)
            throw new IllegalArgumentException("key bytes is null");

        long xecKeyId = NativeInterface.XECKEY_createPublicKey(ockContext.getId(), publicKeyBytes);
        return new XECKey(ockContext, xecKeyId, null, publicKeyBytes.clone());
    }

    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public long getPKeyId() throws OCKException {
        return xecKeyId;
    }

    /**
     * Returns the curve type based on the inputted ObjectID
     * size must not be null if trying to identify an FFDHE curve
     * 
     * @param oid
     * @param size
     * @return curveType
     * @throws IOException
     */
    public static NamedParameterSpec.CURVE getCurve(ObjectIdentifier oid, Integer size)
            throws IOException {
        if (oid == null)
            throw new IOException();
        switch (oid.toString()) {
            case "1.3.101.110":
                return NamedParameterSpec.CURVE.X25519;
            case "1.3.101.111":
                return NamedParameterSpec.CURVE.X448;
            case "1.3.101.112":
                return NamedParameterSpec.CURVE.Ed25519;
            case "1.3.101.113":
                return NamedParameterSpec.CURVE.Ed448;
            case "1.2.840.113549.1.3.1":
                if (size == null)
                    throw new IOException("Received oid: " + oid + " (size is " + size + ")");
                switch (size) {
                    case 2048:
                        return NamedParameterSpec.CURVE.FFDHE2048;
                    case 3072:
                        return NamedParameterSpec.CURVE.FFDHE3072;
                    case 4096:
                        return NamedParameterSpec.CURVE.FFDHE4096;
                    case 6144:
                        return NamedParameterSpec.CURVE.FFDHE6144;
                    case 8192:
                        return NamedParameterSpec.CURVE.FFDHE8192;
                }
        }
        throw new IOException("Received oid: " + oid + " (size is " + size + ")");
    }

    /**
     * Gets the AlgorithmID correlating to the input curve type
     * 
     * @param curve
     * @return algId
     * @throws IOException
     */
    public static AlgorithmId getAlgId(NamedParameterSpec.CURVE curve) throws IOException {
        switch (curve) {
            case Ed25519:
                return new AlgorithmId(AlgorithmId.ed25519_oid);
            case Ed448:
                return new AlgorithmId(AlgorithmId.ed448_oid);
            case X25519:
                return new AlgorithmId(AlgorithmId.x25519_oid);
            case X448:
                return new AlgorithmId(AlgorithmId.x448_oid);
            case FFDHE2048:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE3072:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE4096:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE6144:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE8192:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
        }
        throw new IOException("The current curve is not supported");
    }

    /**
     * Checks whether a curve is of XEC algorithm or not
     * 
     * @param curve
     * @return boolean
     * @throws IOException
     */
    public static boolean isXEC(NamedParameterSpec.CURVE curve) throws IOException {
        return curve.toString().contains("XEC");
    }

    /** Checks whether a curve is of Ed algorithm or not
     *
     * @param curve
     * @return boolean
     * @throws IOException
     */
    public static boolean isEd(NamedParameterSpec.CURVE curve) throws IOException {
        return curve.toString().contains("Ed");
    }

    /**
     * Checks whether a curve is of FFDHE algorithm or not
     * 
     * @param curve
     * @return boolean
     * @throws IOException
     */
    public static boolean isFFDHE(NamedParameterSpec.CURVE curve) throws IOException {
        return curve.toString().contains("FFDHE");
    }

    /**
     * Checks if the oid is valid, throws an exception otherwise
     *
     * @param oid
     * @throws IOException
     */
    public static void checkOid(ObjectIdentifier oid) throws IOException {
        if (oid == null || (!oid.toString().equals("1.3.101.110")
                /* X25519 */ && !oid.toString().equals("1.3.101.111") /* X448 */)
                && !oid.toString().equals("1.3.101.112") /* Ed25519 */
                && !oid.toString().equals("1.3.101.113") /* Ed448 */
                && !oid.toString().equals("1.2.840.113549.1.3.1") /* FFDHE */)
            throw new IOException(
                    "This curve does not seem to be an X25519, X448, Ed25519, Ed448 or FFDHE curve");
    }
}
