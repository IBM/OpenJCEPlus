/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.Signature;
import java.io.EOFException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

abstract class DSASignature extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private Signature signature = null;

    DSASignature(OpenJCEPlusProvider provider, String ockDigestAlgo) {
        try {
            this.provider = provider;
            this.signature = Signature.getInstance(provider.getOCKContext(), ockDigestAlgo, provider);
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize DSA signature", e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (publicKey == null) {
            throw new InvalidKeyException("The Public Key is incorrect.");
        }
        DSAPublicKey dsaPublic = (DSAPublicKey) DSAKeyFactory.toDSAKey(provider, publicKey);

        try {
            this.signature.initialize(dsaPublic.getOCKKey(), false);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException("The Private Key is incorrect.");
        }
        DSAPrivateKey dsaPrivate = (DSAPrivateKey) DSAKeyFactory.toDSAKey(provider, privateKey);

        if (provider.isFIPS()) {
            throw provider.providerException("DSA signing not supported in FIPS", null);
        }
        try {
            this.signature.initialize(dsaPrivate.getOCKKey(), false);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitSign", e);
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] bArray = {b};
        engineUpdate(bArray, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        try {
            this.signature.update(b, off, len);
        } catch (Exception e) {
            SignatureException se = new SignatureException("Failure in engineUpdate");
            provider.setOCKExceptionCause(se, e);
            throw se;
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            return this.signature.sign();
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            return this.signature.verify(sigBytes);
        } catch (Exception e) {
            if (e.getMessage().equals("nested asn1 error")) {
                throw new SignatureException(new EOFException(e.getMessage()));
            }
            // return false rather than throwing exception
            return false;
        }
    }

    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("No parameter accepted");
    }

    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override

    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameter accepted");
        }

    }

    // nested static class for the SHA1withDSA implementation
    public static final class SHA1withDSA extends DSASignature {
        public SHA1withDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA1"); // OCK digest name
        }
    }

    // nested static class for the SHA224withDSA implementation
    public static final class SHA224withDSA extends DSASignature {
        public SHA224withDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA224"); // OCK digest name
        }
    }

    // nested static class for the SHA256withDSA implementation
    public static final class SHA256withDSA extends DSASignature {
        public SHA256withDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA256"); // OCK digest name
        }
    }

    // nested static class for the SHA3_224withDSA implementation
    public static final class SHA3_224withDSA extends DSASignature {
        public SHA3_224withDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-224"); // OCK digest name
        }
    }

    // nested static class for the SHA3_256withDSA implementation
    public static final class SHA3_256withDSA extends DSASignature {
        public SHA3_256withDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-256"); // OCK digest name
        }
    }

    // nested static class for the SHA3_384withDSA implementation
    public static final class SHA3_384withDSA extends DSASignature {
        public SHA3_384withDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-384"); // OCK digest name
        }
    }

    // nested static class for the SHA3_512withDSA implementation
    public static final class SHA3_512withDSA extends DSASignature {
        public SHA3_512withDSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-512"); // OCK digest name
        }
    }
}
