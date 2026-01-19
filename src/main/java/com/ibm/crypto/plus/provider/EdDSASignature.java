/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.SignatureEdDSA;
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
import java.security.spec.EdDSAParameterSpec;

abstract class EdDSASignature extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private SignatureEdDSA signature = null;
    private ByteArrayOutputStream message = null;
    private String alg = null;
    private boolean privateKeyInit = false;
    private boolean publicKeyInit = false;

    EdDSASignature(OpenJCEPlusProvider provider) {
        try {
            this.provider = provider;
            this.signature = SignatureEdDSA.getInstance(provider.getOCKContext());
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize EdDSA signature", e);
        }
    }

    EdDSASignature(OpenJCEPlusProvider provider, String Alg) {
        try {
            this.provider = provider;
            this.signature = SignatureEdDSA.getInstance(provider.getOCKContext());
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize EdDSA signature", e);
        }
        this.alg = Alg; // Added to know difference between ed25519 and ed448
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
        }
        // engineSet is added to resolve iterop issue with JCK case 569 and maintain compatibility with Sun
        // input params and operation are checked.
        // This edDSA singature is using default mode (Ed25519 or Ed448)
        // for edDSAParameterSpec (context = null, prehash = false)
        if (params instanceof EdDSAParameterSpec edParams) {
            if (edParams.isPrehash() || !edParams.getContext().isEmpty()) {
                throw new InvalidAlgorithmParameterException(
                        "The EdDSA signature only supports the default mode (Ed25519 or Ed448),"
                        + " where the EdDSAParameterSpec context is null and prehash is set to false");
            }
            if (message != null) {
                // Sign/Verify is in progress
                throw new InvalidParameterException(
                        "Cannot change signature parameters during operation");
            }
        } else {
            throw new InvalidAlgorithmParameterException("Only EdDSAParameterSpec supported");
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    private void ensureMessageInit() throws SignatureException {
        if (message == null) {
            if (this.signature == null) {
                throw new SignatureException("Not initialized");
            }
            message = new ByteArrayOutputStream();
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        EdDSAPrivateKeyImpl edDSAPrivate = null;
        try {
            edDSAPrivate = (EdDSAPrivateKeyImpl) new EdDSAKeyFactory(provider)
                    .engineTranslateKey(privateKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Unsupported key type: " + e.getMessage());
        }

        //Validate that the alg of the key matchs the alg specified on creation of this object
        if (this.alg != null && !((edDSAPrivate.getParams().getName()).equals(this.alg))) {
            throw new InvalidKeyException("Key must be of algorithm " + this.alg);
        }

        try {
            this.signature.initialize(edDSAPrivate.getOCKKey());
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitSign", e);
        }
        // Set to sign mode and reset message
        this.privateKeyInit = true;
        this.publicKeyInit = false;
        this.message = null;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        EdDSAPublicKeyImpl edDSAPublic = null;
        try {
            edDSAPublic = (EdDSAPublicKeyImpl) new EdDSAKeyFactory(provider)
                    .engineTranslateKey(publicKey);
        } catch (Exception e) {
            throw new InvalidKeyException("Unsupported key type: " + e.getMessage());
        }
        //Validate that the alg of the key matchs the alg specified on creation of this object
        if (this.alg != null && !((edDSAPublic.getParams().getName()).equals(this.alg))) {
            throw new InvalidKeyException("Key must be of algorithm " + this.alg);
        }
        try {
            this.signature.initialize(edDSAPublic.getOCKKey());
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }

        // Set to verify mode and reset message
        this.privateKeyInit = false;
        this.publicKeyInit = true;
        this.message = null;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (!privateKeyInit) {
            throw new SignatureException("Missing private key");
        }
        ensureMessageInit();
        try {
            byte[] dataBytes = message.toByteArray();
            message = null;
            return this.signature.sign(dataBytes);
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }


    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] bArray = {b};
        engineUpdate(bArray, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        ensureMessageInit();
        // update can be called several times, as this is required by JCK 569 to maintain interop with Sun
        message.write(b, off, len);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (!publicKeyInit) {
            throw new SignatureException("Missing public key");
        }

        try {
            ensureMessageInit();
            byte[] messageBytes = message.toByteArray();
            message = null;
            return this.signature.verify(sigBytes, messageBytes);
        } catch (Exception e) {
            // return false rather than throwing exception
            return false;
        }
    }

    // nested static class for the Ed25519 implementation
    public static final class Ed25519 extends EdDSASignature {
        public Ed25519(OpenJCEPlusProvider provider) {
            super(provider, "Ed25519");
        }

    }

    // nested static class for the Ed448 implementation
    public static final class Ed448 extends EdDSASignature {
        public Ed448(OpenJCEPlusProvider provider) {
            super(provider, "Ed448");
        }
    }

    // nested static class for the Ed448 implementation
    public static final class EdDSA extends EdDSASignature {
        public EdDSA(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }
}
