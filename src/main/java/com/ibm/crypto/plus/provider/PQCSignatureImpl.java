/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.PQCSignature;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

abstract class PQCSignatureImpl extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private PQCSignature signature = null;
    private final ByteArrayOutputStream message = new ByteArrayOutputStream();
    private String alg = null;
    private boolean privateKeyInit = false;
    private boolean publicKeyInit = false;
    private final static String debPrefix = "PQCSIGNATUREImpl";


    PQCSignatureImpl(OpenJCEPlusProvider provider) {
        try {
            this.provider = provider;
            this.signature = PQCSignature.getInstance(provider.getOCKContext());
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize EdDSA signature", e);
        }
    }

    PQCSignatureImpl(OpenJCEPlusProvider provider, String Alg) {
        try {
            this.provider = provider;
            this.signature = PQCSignature.getInstance(provider.getOCKContext());
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize EdDSA signature", e);
        }
        this.alg = Alg; // Added to know difference between algorithms.
    }

    @Deprecated
    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    @Deprecated
    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params == null) {
            return;
        } else {
            throw new InvalidAlgorithmParameterException("Algorithm does not support parameters.");
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        PQCPrivateKey keyPrivate = null;
        try {
            keyPrivate = (PQCPrivateKey) PQCKeyFactory.toPQCKey(provider, privateKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Unsupported key type: ", e);
        }

        // Validate that the alg of the key matches the alg specified on creation of this object.
        if (this.alg != null && !((keyPrivate.getAlgorithm()).equalsIgnoreCase(this.alg))) {
            throw new InvalidKeyException("Key must be of algorithm " + this.alg);
        }

        try {
            this.signature.initialize(keyPrivate.getPQCKey());
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitSign", e);
        }
        // Set to sign mode and reset message.
        this.privateKeyInit = true;
        this.publicKeyInit = false;
        this.message.reset();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        PQCPublicKey keyPublic = null;
        try {
            keyPublic = (PQCPublicKey) PQCKeyFactory.toPQCKey(provider, publicKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Unsupported key type: ", e);
        }
        // Validate that the alg of the key matches the alg specified on creation of this object.
        if (this.alg != null && !((keyPublic.getAlgorithm()).equalsIgnoreCase(this.alg))) {
            throw new InvalidKeyException("Expected algorithm " + this.alg + ", but got " + keyPublic.getAlgorithm());
        }
        try {
            this.signature.initialize(keyPublic.getPQCKey());
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }

        // Set to verify mode and reset message.
        this.privateKeyInit = false;
        this.publicKeyInit = true;
        this.message.reset();
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!privateKeyInit) {
            throw new SignatureException("Missing private key");
        }

        try {
            byte[] dataBytes = message.toByteArray();
            message.reset();
            byte[] sign = this.signature.sign(dataBytes);
            return sign;
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }


    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        message.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        // Update can be called several times, as this is required by JCK 569 to maintain interop with Sun.
        message.write(b, off, len);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (!publicKeyInit) {
            throw new SignatureException("Missing public key");
        }
        if (message == null) {
            return false;
        }

        try {
            byte[] messageBytes = message.toByteArray();
            message.reset();
            return this.signature.verify(sigBytes, messageBytes);
        } catch (Exception e) {
            // Return false rather than throwing exception.
            return false;
        }
    }

    public static final class MLDSA44 extends PQCSignatureImpl {

        public MLDSA44(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-44");
        }
    }

    public static final class MLDSA65 extends PQCSignatureImpl {

        public MLDSA65(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-65");
        }
    }

    public static final class MLDSA87 extends PQCSignatureImpl {

        public MLDSA87(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-87");
        }
    }

    public static final class SLHDSASHA2128s extends PQCSignatureImpl {

        public SLHDSASHA2128s(OpenJCEPlusProvider provider) {

            super(provider, "SLH-DSA-SHA2-128s");
        }
    }

    public static final class SLHDSASHAKE128s extends PQCSignatureImpl {

        public SLHDSASHAKE128s(OpenJCEPlusProvider provider) {

            super(provider, "SLH-DSA-SHAKE-128s");
        }
    }

    public static final class SLHDSASHA2128f extends PQCSignatureImpl {

        public SLHDSASHA2128f(OpenJCEPlusProvider provider) {

            super(provider, "SLH-DSA-SHA2-128f");
        }
    }

    public static final class SLHDSASHAKE128f extends PQCSignatureImpl {

        public SLHDSASHAKE128f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-128f");
        }
    }

    public static final class SLHDSASHA2192s extends PQCSignatureImpl {

        public SLHDSASHA2192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192s");
        }
    }

    public static final class SLHDSASHAKE192s extends PQCSignatureImpl {

        public SLHDSASHAKE192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192s");
        }
    }

    public static final class SLHDSASHA2192f extends PQCSignatureImpl {

        public SLHDSASHA2192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192f");
        }
    }

    public static final class SLHDSASHAKE192f extends PQCSignatureImpl {

        public SLHDSASHAKE192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192f");
        }
    }

    public static final class SLHDSASHA2256s extends PQCSignatureImpl {

        public SLHDSASHA2256s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256s");
        }
    }

    public static final class SLHDSASHAKE256s extends PQCSignatureImpl {

        public SLHDSASHAKE256s(OpenJCEPlusProvider provider) {

            super(provider, "SLH-DSA-SHAKE-256s");
        }
    }

    public static final class SLHDSASHA2256f extends PQCSignatureImpl {

        public SLHDSASHA2256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256f");
        }
    }

    public static final class SLHDSASHAKE256f extends PQCSignatureImpl {

        public SLHDSASHAKE256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-256f");
        }
    }
}
