/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

public final class ECKey implements AsymmetricKey {

    private static final String ALLOW_INCORRECT_KEYSIZES = "openjceplus.ec.allowIncorrectKeysizes";
    private static final boolean allowIncorrectKeysizes = Boolean.parseBoolean(System.getProperty(ALLOW_INCORRECT_KEYSIZES, "false"));

    // The following is a special byte[] instance to indicate that the
    // private/public key bytes are available but not yet obtained.
    //
    static final byte[] unobtainedKeyBytes = new byte[0];

    private OCKContext ockContext;
    private long ecKeyId = 0;
    private long pkeyId = 0;
    private static final String badIdMsg = "EC Key Identifier is not valid";

    // Public Key
    // BigInteger pubKeyAffineX;
    // BigInteger pubKeyAffineY;

    // Private Key
    private BigInteger s;
    // ECParameterSpec prSpec;

    // EcparameterSpec
    ECParameterSpec ecSpec;
    // private int cofactor; // same as h
    // private byte [] order; // same as n
    // ECPoint g; //genAffineX, genAffineY
    // EllipticCurve curve

    // boolean isNamedCurve;

    // ECGenParameterSpec
    // String curveName;

    // EllipticCurve curve
    // ECFiled field
    // BigInteger a
    // BigInteger b

    // ECField: ECFieldF2m || ECFieldFp

    // ECFieldFp
    BigInteger p;

    // private byte [] b;
    private byte[] privateKeyBytes;
    private byte[] parameterBytes;
    private byte[] publicKeyBytes;

    private static final String debPrefix = "ECKey";

    private ECKey(OCKContext ockContext, long ecKeyId, byte[] parameterBytes,
            byte[] privateKeyBytes, byte[] publicKeyBytes) {
        //final String methodName = "ECKey(long, byte[], byte[], byte[]) ";
        this.ockContext = ockContext;
        this.ecKeyId = ecKeyId;
        this.pkeyId = 0;
        this.parameterBytes = parameterBytes;
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyBytes = publicKeyBytes;
        //OCKDebug.Msg (debPrefix, methodName, "privateKeyBytes :", privateKeyBytes); 
        //OCKDebug.Msg (debPrefix, methodName, "publicKeyBytes :", publicKeyBytes);  
        //OCKDebug.Msg (debPrefix, methodName, "parameterBytes :", parameterBytes);
    }

    /* Custom Curve */
    private ECKey(OCKContext ockContext, long ecKeyId, ECParameterSpec ecSpec, BigInteger s,
            BigInteger pubKeyAffineX, BigInteger pubKeyAffineY) {
        this.ockContext = ockContext;
        this.ecKeyId = ecKeyId;
        this.pkeyId = 0;

        this.ecSpec = ecSpec;
        // this.isNamedCurve = false;
        // this.curveName = null;
        // this.parameterBytes = convertSpecToBytes(ecSpec);

        this.s = s;
        // this.pubKeyAffineX = pubKeyAffineX;
        // this.pubKeyAffineY = pubKeyAffineY;

    }

    // Note that the caller of this method must ensure the pointer ecKeyId is not used
    // concurrently by suitable locking.
    protected static byte[] getParametersBytes(OCKContext ockContext, long ecKeyId)
            throws OCKException {
        return (NativeInterface.ECKEY_getParameters(ockContext.getId(), ecKeyId));
    }


    public static ECKey generateKeyPair(OCKContext ockContext, int size, SecureRandom random)
            throws OCKException {
        //final String methodName = "generateKeyPair ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (size < 0) {
            throw new IllegalArgumentException("The key length parameter is invalid");
        }

        long ecKeyId;
        try {
            ecKeyId = NativeInterface.ECKEY_generate(ockContext.getId(), size);
        } catch (OCKException oe){
            if (oe.getMessage().contains("Incorrect key size") && allowIncorrectKeysizes) {
                // If the flag is set and an incorrect key size was provided, default to 256.
                ecKeyId = NativeInterface.ECKEY_generate(ockContext.getId(), 256);
            } else {
                throw oe;
            }
        }
        
        if (!validId(ecKeyId)) {
            throw new OCKException(badIdMsg);
        }

        byte[] parameterBytes = getParametersBytes(ockContext, ecKeyId);
        //OCKDebug.Msg (debPrefix, methodName,  "size=" + size + " ecKeyId=" + ecKeyId + " parameterBytes :",  parameterBytes);
        return new ECKey(ockContext, ecKeyId, parameterBytes, unobtainedKeyBytes,
                unobtainedKeyBytes);
    }


    public static ECKey generateKeyPair(OCKContext ockContext, String soid, SecureRandom random)
            throws OCKException {
        //final String methodName = "generateKeyPair(String, SecureRandom) ";
        if (ockContext == null) {
            throw new IllegalArgumentException("The context parameter is null");
        }

        if ((soid == null) || (soid.equals("") == true)) {
            throw new IllegalArgumentException("The String Object Identifier parameter is invalid");
        }

        long ecKeyId = NativeInterface.ECKEY_generate(ockContext.getId(), soid);
        if (!validId(ecKeyId)) {
            throw new OCKException(badIdMsg);
        }
        byte[] parameterBytes = getParametersBytes(ockContext, ecKeyId);
        //OCKDebug.Msg (debPrefix, methodName, "soid :" + soid + " ecKeyId :" + ecKeyId + "parameterBytes :",  parameterBytes);
        return new ECKey(ockContext, ecKeyId, parameterBytes, unobtainedKeyBytes,
                unobtainedKeyBytes);

    }

    public static ECKey generateKeyPair(OCKContext ockContext, byte[] parameterBytes,
            SecureRandom random) throws OCKException {
        //final String methodName = "generateKeyPair(byte[], SecureRandom) ";
        if (ockContext == null) {
            throw new IllegalArgumentException("The context parameter is null");
        }

        if (parameterBytes == null) {
            throw new IllegalArgumentException("The parameter bytes is null");
        }

        //OCKDebug.Msg (debPrefix, methodName, "paramBytes.length :" + parameterBytes.length,  parameterBytes);
        long ecKeyId = NativeInterface.ECKEY_generate(ockContext.getId(), parameterBytes);
        //OCKDebug.Msg (debPrefix, methodName, "ecKeyId :" + ecKeyId);
        return new ECKey(ockContext, ecKeyId, parameterBytes, unobtainedKeyBytes,
                unobtainedKeyBytes);
    }

    public static byte[] generateParameters(OCKContext ockContext, int size) throws OCKException {
        //final String methodName = "generateParameters (int) ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (size < 0) {
            throw new IllegalArgumentException("key length is invalid");
        }

        //OCKDebug.Msg (debPrefix, methodName, "size :" + size);
        return NativeInterface.ECKEY_generateParameters(ockContext.getId(), size);
    }

    public static byte[] generateParameters(OCKContext ockContext, String soid)
            throws OCKException {
        //final String methodName = "generateParameters(soid) ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (soid == null || soid.equals("")) {
            throw new IllegalArgumentException(
                    "Curve's object identifier(String) cannot be null or empty");
        }

        //OCKDebug.Msg (debPrefix, methodName, "soid :" + soid);
        byte[] generatedParams = NativeInterface.ECKEY_generateParameters(ockContext.getId(), soid);
        //OCKDebug.Msg (debPrefix, methodName,  "generatedParams :", generatedParams);
        return generatedParams;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    public long getEcKeyId() {
        return ecKeyId;
    }

    @Override
    public long getPKeyId() throws OCKException {
        if (pkeyId == 0) {
            obtainPKeyId();
        }

        return pkeyId;
    }

    public byte[] getParameters() throws OCKException {
        //final String methodName = "getParameters :";
        if (ecSpec == null) {
            obtainParameters();
        }
        //OCKDebug.Msg (debPrefix, methodName,  parameterBytes);
        return (parameterBytes == null) ? null : parameterBytes;
    }

    //    public static ECPoint buildPublicKey(BigInteger s, ECParameterSpec params) {
    //        /* Let OCK compute the public key */
    //        return null;
    //    }

    @Override
    public byte[] getPrivateKeyBytes() throws OCKException {
        //final String methodName = "getPrivateKeyBytes()";
        if (privateKeyBytes == unobtainedKeyBytes) {
            obtainPrivateKeyBytes();
        }
        //OCKDebug.Msg (debPrefix, methodName,  privateKeyBytes);
        return (privateKeyBytes == null) ? null : privateKeyBytes.clone();
    }

    @Override
    public byte[] getPublicKeyBytes() throws OCKException {
        //final String methodName = "getPublickeyBytes()";
        if (publicKeyBytes == unobtainedKeyBytes) {
            obtainPublicKeyBytes();
        }
        //OCKDebug.Msg (debPrefix, methodName, publicKeyBytes);
        return (publicKeyBytes == null) ? null : publicKeyBytes.clone();
    }

    private synchronized void obtainPKeyId() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPKeyId at the same time, we only want to call the native
        // code one time.
        //
        if (pkeyId == 0) {
            if (!validId(ecKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.pkeyId = NativeInterface.ECKEY_createPKey(ockContext.getId(), ecKeyId);
        }
    }

    private synchronized void obtainParameters() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getParameters at the same time, we only want to call the
        // native code one time.
        //
        if (ecSpec == null) {
            if (!validId(ecKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.parameterBytes = NativeInterface.ECKEY_getParameters(ockContext.getId(), ecKeyId);
        }
    }

    private synchronized void obtainPrivateKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPrivateKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (privateKeyBytes == unobtainedKeyBytes) {
            if (!validId(ecKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.privateKeyBytes = NativeInterface.ECKEY_getPrivateKeyBytes(ockContext.getId(),
                    ecKeyId);

        }
    }

    private synchronized void obtainPublicKeyBytes() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to getPublicKeyBytes at the same time, we only want to call the
        // native code one time.
        //
        if (publicKeyBytes == unobtainedKeyBytes) {
            if (!validId(ecKeyId)) {
                throw new OCKException(badIdMsg);
            }
            this.publicKeyBytes = NativeInterface.ECKEY_getPublicKeyBytes(ockContext.getId(),
                    ecKeyId);
        }
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        //final String methodName = "finalize ";
        //OCKDebug.Msg(debPrefix, methodName,  "ecKeyId :" + ecKeyId + " pkeyId=" + pkeyId);
        try {
            if ((privateKeyBytes != null) && (privateKeyBytes != unobtainedKeyBytes)) {
                Arrays.fill(privateKeyBytes, (byte) 0x00);
            }

            if (ecKeyId != 0) {
                NativeInterface.ECKEY_delete(ockContext.getId(), ecKeyId);
                ecKeyId = 0;
            }

            if (pkeyId != 0) {
                NativeInterface.PKEY_delete(ockContext.getId(), pkeyId);
                pkeyId = 0;
            }
        } finally {
            super.finalize();
        }
    }

    // The underlying native function used in this method does not use any native pointer
    // that is shared across threads. Hence, it does not require any locks
    public static ECKey createPrivateKey(OCKContext ockContext, byte[] privateKeyBytes,
            byte[] paramBytes) throws OCKException {
        //final String methodName = "createPrivateKey";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (privateKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }

        //OCKDebug.Msg (debPrefix, methodName,  "privateKeyBytes :", privateKeyBytes );
        long ecKeyId = NativeInterface.ECKEY_createPrivateKey(ockContext.getId(), privateKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName, "ecPrivateKeyId :" + ecKeyId);
        if (!validId(ecKeyId)) {
            throw new OCKException(badIdMsg);
        }
        byte[] publicKeyBytes = NativeInterface.ECKEY_getPublicKeyBytes(ockContext.getId(),
                ecKeyId);

        //OCKDebug.Msg (debPrefix, methodName, "publicKeyBytes :", publicKeyBytes);
        return new ECKey(ockContext, ecKeyId, paramBytes, privateKeyBytes.clone(), publicKeyBytes);
    }

    // There is a lock on ecPrivateKey to ensure that the underlying native pointer is not concurrently
    // used by another ECDSA operation. This is needed as the method
    // ECKEY.signDatawithECDSA is not synchronized and not thread safe.
    // The method ECKey.signDatawithECDSA should NOT be synchronized for performance as that would create a global lock.
    public static byte[] signDatawithECDSA(OCKContext ockContext, byte[] digestBytes,
            int digestBytesLen, ECKey ecPrivateKey) throws OCKException {
        //final String methodName = "signDatawithECDSA";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (digestBytes == null || digestBytesLen < 1) {
            throw new IllegalArgumentException("digest bytes is null");
        }
        byte[] digestActualBytes = null;
        if (digestBytes.length != digestBytesLen) {
            digestActualBytes = Arrays.copyOfRange(digestBytes, 0, digestBytesLen);
        } else {
            digestActualBytes = digestBytes;
        }

        if (!validId(ecPrivateKey.getEcKeyId())) {
            throw new OCKException(badIdMsg);
        }

        byte[] signedBytes;
        synchronized (ecPrivateKey) {
            //OCKDebug.Msg (debPrefix, methodName,  "digestBytesLen :" + digestBytesLen +  " digestActualBytes :", digestActualBytes);
            signedBytes = NativeInterface.ECKEY_signDatawithECDSA(ockContext.getId(),
                    digestActualBytes, digestBytesLen, ecPrivateKey.getEcKeyId());
        }
        //OCKDebug.Msg (debPrefix, methodName,  " signedBytes :" + signedBytes);
        return signedBytes;
    }

    // There is a lock on ecPublicKey to ensure that the underlying native
    // pointers are not concurrently used by another ECDSA operation. This is needed as the method
    // ECKey.verifyDatawithECDSA is not synchronized and not thread safe.
    // The method ECKey.verifyDatawithECDSA should NOT be synchronized for performance as that would create a global lock.
    public static boolean verifyDatawithECDSA(OCKContext ockContext, byte[] digestBytes,
            int digestBytesLen, byte[] sigBytes, int sigBytesLen, ECKey ecPublicKey)
            throws OCKException {
        //final String methodName = "verifyDatawithECDSA";
        boolean verified = false;
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (digestBytes == null || digestBytesLen < 1) {
            throw new IllegalArgumentException("digest bytes are null");
        }

        if (sigBytes == null || sigBytesLen < 1) {
            throw new IllegalArgumentException("signature bytes are null");
        }

        byte[] digestActualBytes = null;
        if (digestBytes.length != digestBytesLen) {
            digestActualBytes = Arrays.copyOfRange(digestBytes, 0, digestBytesLen);
        } else {
            digestActualBytes = digestBytes;
        }

        byte[] sigActualBytes = null;
        if (sigBytes.length != sigBytesLen) {

            sigActualBytes = Arrays.copyOfRange(sigBytes, 0, sigBytesLen);
        } else {
            sigActualBytes = sigBytes;
        }

        if (!validId(ecPublicKey.getEcKeyId())) {
            throw new OCKException(badIdMsg);
        }
        //OCKDebug.Msg (debPrefix, methodName, "diestBytesLen : " + digestBytesLen + " digestAcutalBytes : ", digestActualBytes);
        //OCKDebug.Msg (debPrefix, methodName, " sigActualBytes : ", sigActualBytes);
        synchronized (ecPublicKey) {
            verified = NativeInterface.ECKEY_verifyDatawithECDSA(ockContext.getId(),
                    digestActualBytes, digestBytesLen, sigActualBytes, sigBytesLen,
                    ecPublicKey.getEcKeyId());
        }
        //OCKDebug.Msg (debPrefix, methodName,  verified);
        return verified;
    }

    public static ECKey createPublicKey(OCKContext ockContext, byte[] publicKeyBytes,
            byte[] parameterBytes) throws OCKException {
        //final String methodName = "createPublicKey";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("key bytes is null");
        }
        //OCKDebug.Msg (debPrefix, methodName,  "publicKeyBytes :",  publicKeyBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "parameterBytes :", parameterBytes);
        long ecKeyId = NativeInterface.ECKEY_createPublicKey(ockContext.getId(), publicKeyBytes,
                parameterBytes);
        //OCKDebug.Msg (debPrefix, methodName,  "ecKeyId :" + ecKeyId);
        return new ECKey(ockContext, ecKeyId, null, null, publicKeyBytes.clone());
    }

    // There is a double lock on pubEcKeyId and privEcKeyId to ensure that the underlying native
    // pointers are not concurrently used by another ECDH operation. This is needed as the method
    // ECKey.computeDHSecret is not synchronized and not thread safe.
    // The method ECKey.computeDHSecret should NOT be synchronized for performance as that would create a global lock.
    public static byte[] computeECDHSecret(OCKContext ockContext, long pubEcKeyId, long privEcKeyId)
            throws OCKException {
        //final String methodName = "computeECDHSecret ";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (pubEcKeyId == 0) {
            throw new IllegalArgumentException("The public key parameter is not valid");
        }

        if (privEcKeyId == 0) {
            throw new IllegalArgumentException("The private key parameter is not valid");
        }

        byte[] sharedSecretBytes = NativeInterface.ECKEY_computeECDHSecret(ockContext.getId(),
                pubEcKeyId, privEcKeyId);
        //OCKDebug.Msg (debPrefix, methodName,  "pubEcKeyId :" + pubEcKeyId + " privEcKeyId :" + privEcKeyId + " sharedSecretBytes :", sharedSecretBytes);
        return sharedSecretBytes;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "id :" + id);
        return (id != 0L);
    }

}
