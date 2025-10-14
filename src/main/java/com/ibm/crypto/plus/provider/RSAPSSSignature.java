/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.SignatureRSAPSS;
import com.ibm.crypto.plus.provider.ock.SignatureRSAPSS.InitOp;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Hashtable;

/**
 * PKCS#1 RSA-PSS signatures with the various message digest algorithms. This
 * file contains an abstract base class with all the logic plus a nested static
 * class for each of the message digest algorithms (see end of the file). Only
 * SHA-1, SHA-256, SHA-384, and SHA-512 are recommended for EMSA-PSS encoding
 * schemes per RFC.
 *
 */
public final class RSAPSSSignature extends SignatureSpi {

    protected SecureRandom random;

    private OpenJCEPlusProvider provider = null;
    private SignatureRSAPSS signature = null;

    // PSS parameters
    PSSParameterSpec pssParameterSpec = null; //PSSParameterSpec.DEFAULT;

    private static final Hashtable<String, Integer> DIGEST_LENGTHS = new Hashtable<String, Integer>();
    static {
        DIGEST_LENGTHS.put("SHA-1", 20);
        DIGEST_LENGTHS.put("SHA", 20);
        DIGEST_LENGTHS.put("SHA1", 20);
        DIGEST_LENGTHS.put("SHA-224", 28);
        DIGEST_LENGTHS.put("SHA224", 28);
        DIGEST_LENGTHS.put("SHA-256", 32);
        DIGEST_LENGTHS.put("SHA256", 32);
        DIGEST_LENGTHS.put("SHA-384", 48);
        DIGEST_LENGTHS.put("SHA384", 48);
        DIGEST_LENGTHS.put("SHA-512", 64);
        DIGEST_LENGTHS.put("SHA512", 64);
        DIGEST_LENGTHS.put("MD5", 16);
        DIGEST_LENGTHS.put("SHA-512/224", 28);
        DIGEST_LENGTHS.put("SHA512/224", 28);
        DIGEST_LENGTHS.put("SHA-512/256", 32);
        DIGEST_LENGTHS.put("SHA512/256", 32);
    }

    // private key, if initialized for signing
    private java.security.interfaces.RSAPrivateKey privateKey;
    // public key, if initialized for verifying
    private java.security.interfaces.RSAPublicKey publicKey;

    public RSAPSSSignature(OpenJCEPlusProvider provider, PSSParameterSpec pssParameterSpec) {
        this.provider = provider;
        try {
            if (pssParameterSpec == null) {
                if (provider.isFIPS()) {
                    pssParameterSpec = new PSSParameterSpec("SHA-224", "MGF1",
                            MGF1ParameterSpec.SHA224, 32, 1);
                } else {
                    pssParameterSpec = new PSSParameterSpec("SHA1", "MGF1", MGF1ParameterSpec.SHA1,
                            20, 1);
                }
            }

            MGF1ParameterSpec mgf1ParamSpec = (MGF1ParameterSpec) pssParameterSpec
                    .getMGFParameters();
            if ((pssParameterSpec.getDigestAlgorithm().equalsIgnoreCase("SHA1")
                    || pssParameterSpec.getDigestAlgorithm().equalsIgnoreCase("SHA-1")
                    || pssParameterSpec.getDigestAlgorithm().equalsIgnoreCase("SHA"))
                    && (provider.isFIPS())) {
                throw provider.providerException("SHA1 not supported by FIPS.", null);
            }
            this.signature = SignatureRSAPSS.getInstance(provider.getOCKContext(),
                    pssParameterSpec.getDigestAlgorithm(), pssParameterSpec.getSaltLength(),
                    pssParameterSpec.getTrailerField(), pssParameterSpec.getMGFAlgorithm(),
                    mgf1ParamSpec.getDigestAlgorithm(), provider);
            engineSetParameter(pssParameterSpec);
        } catch (InvalidAlgorithmParameterException e) {
            throw new ProviderException(e);
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize RSAPSS signature", e);
        }
    }

    /**
     * Construct a new RSAPSSSignature. Used by subclasses.
     */
    public RSAPSSSignature(OpenJCEPlusProvider provider) {
        // PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-1", "MGF1",
        // MGF1ParameterSpec.SHA1,20, 1);
        this(provider, (PSSParameterSpec) null);
    }

    public RSAPSSSignature(OpenJCEPlusProvider provider, String ockDigestAlgo) {
        // PSSParameterSpec pssParameterSpec = null;
        try {
            this.provider = provider;
            if (pssParameterSpec != null) {
                //System.out.println ("pssParameterSpec is null");
                switch (ockDigestAlgo) {
                    case "SHA-1":
                        if (provider.isFIPS()) {
                            throw provider.providerException("SHA1 not supported by FIPS.", null);
                        }
                        pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1",
                                MGF1ParameterSpec.SHA1, 20, 1);
                        break;
                    case "SHA-224":
                        pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1",
                                MGF1ParameterSpec.SHA224, 32, 1);
                        break;
                    case "SHA-256":
                        pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1",
                                MGF1ParameterSpec.SHA256, 32, 1);
                        break;
                    case "SHA-384":
                        pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1",
                                MGF1ParameterSpec.SHA384, 64, 1);
                        break;
                    case "SHA-512":
                        pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1",
                                MGF1ParameterSpec.SHA512, 64, 1);
                        break;
                    // case "SHA-512/224":
                    //         pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1", MGF1ParameterSpec.SHA512_224, 28, 1);
                    //         break;
                    // case "SHA-512/256":
                    //         pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1", MGF1ParameterSpec.SHA512_256, 32, 1);
                    //         break;
                    default:
                        if (provider.isFIPS()) {
                            pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1",
                                    MGF1ParameterSpec.SHA224, 32, 1);
                        } else {
                            pssParameterSpec = new PSSParameterSpec(ockDigestAlgo, "MGF1",
                                    MGF1ParameterSpec.SHA1, 20, 1);
                        }
                        break;

                }

            }
            MGF1ParameterSpec mgf1ParamSpec = (MGF1ParameterSpec) pssParameterSpec
                    .getMGFParameters();
            this.signature = SignatureRSAPSS.getInstance(provider.getOCKContext(), ockDigestAlgo,
                    pssParameterSpec.getSaltLength(), pssParameterSpec.getTrailerField(),
                    pssParameterSpec.getMGFAlgorithm(), mgf1ParamSpec.getDigestAlgorithm(), provider);
            //System.out.println("In get Instance " + this.signature);
            engineSetParameter(pssParameterSpec);

        } catch (InvalidAlgorithmParameterException e) {
            throw new ProviderException(e);
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize RSAPSS signature", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof java.security.interfaces.RSAPrivateKey)) {
            throw new InvalidKeyException("Key is not an RSAPrivateKey");
        }

        Integer hLen = null;
        // validate the key length
        if (this.pssParameterSpec != null) {
            hLen = DIGEST_LENGTHS.get(this.pssParameterSpec.getDigestAlgorithm());
            if (hLen == null) {
                throw new ProviderException("Unsupported digest algorithm: "
                        + this.pssParameterSpec.getDigestAlgorithm());
            }
        }

        //RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) RSAKeyFactory.toRSAKey(provider, privateKey);
        PrivateKey rsaPrivate = (PrivateKey) RSAKeyFactory.toRSAKey(provider, privateKey);
        checkKeyIsValid((RSAKey) rsaPrivate);
        try {
            checkKeyLength((RSAKey) rsaPrivate, hLen, this.pssParameterSpec.getSaltLength());
        } catch (SignatureException se) {
            throw new InvalidKeyException("Key has incorrect length " + se.getMessage());
        }



        if (rsaPrivate == privateKey) {
            // If we are using the user-supplied key, then make a clone of the
            // key to use with OCK. OCK holds state information with the key and
            // the same key should not be used for both Cipher and signature,
            // nor with different signature algorithms. To ensure this we
            // use a clone of the key for the Signature operations. If we
            // translated the user-supplied key then no need to use a clone
            // since we already created a new key.
            //
            PrivateKey rsaPrivateClone = null;
            if (rsaPrivate instanceof RSAPrivateCrtKey) {
                rsaPrivateClone = new RSAPrivateCrtKey(provider, rsaPrivate.getEncoded());
            } else if (rsaPrivate instanceof RSAPrivateKey) {
                rsaPrivateClone = new RSAPrivateKey(provider, rsaPrivate.getEncoded());
            }
            rsaPrivate = rsaPrivateClone;
        }

        try {
            if (rsaPrivate instanceof RSAPrivateCrtKey) {
                this.signature.initialize(((RSAPrivateCrtKey) rsaPrivate).getOCKKey(),
                        InitOp.INITSIGN, false);
            } else if (rsaPrivate instanceof RSAPrivateKey) {
                this.signature.initialize(((RSAPrivateKey) rsaPrivate).getOCKKey(), InitOp.INITSIGN,
                        true);
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitSign", e);
        }
        this.privateKey = (java.security.interfaces.RSAPrivateKey) rsaPrivate;
        this.publicKey = null;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey)) {
            throw new InvalidKeyException("Key is not an RSAPublicKey");
        }
        Integer hLen = null;

        // validate the key length
        if (this.pssParameterSpec != null) {
            hLen = DIGEST_LENGTHS.get(this.pssParameterSpec.getDigestAlgorithm());
            if (hLen == null) {
                throw new ProviderException("Unsupported digest algorithm: "
                        + this.pssParameterSpec.getDigestAlgorithm());
            }
        }

        RSAPublicKey rsaPublic = (RSAPublicKey) RSAKeyFactory.toRSAKey(provider, publicKey);
        checkKeyIsValid(rsaPublic);
        try {
            checkKeyLength(rsaPublic, hLen, this.pssParameterSpec.getSaltLength());
        } catch (SignatureException se) {
            throw new InvalidKeyException("Key has incorrect length" + se.getMessage());
        }

        if (rsaPublic == publicKey) {
            // If we are using the user-supplied key, then make a clone of the
            // key to use with OCK. OCK holds state information with the key and
            // the same key should not be used for both Cipher and signature,
            // nor with different signature algorithms. To ensure this we
            // use a clone of the key for the Signature operations. If we
            // translated the user-supplied key then no need to use a clone
            // since we already created a new key.
            //
            RSAPublicKey rsaPublicClone = new RSAPublicKey(provider, rsaPublic.getEncoded());
            rsaPublic = rsaPublicClone;
        }

        try {
            this.signature.initialize(rsaPublic.getOCKKey(), InitOp.INITVERIFY, false);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }

        this.publicKey = rsaPublic;
        this.privateKey = null;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        byte[] bArray = {b};
        engineUpdate(bArray, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        ensureInit();
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
            return this.signature.signFinal();
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }


    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        try {
            boolean result = this.signature.verifyFinal(sigBytes);
            return result;
        } catch (Exception e) {
            // return false rather than throwing exception
            return false;
        }
    }

    // set parameter, not supported. See JCA doc
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    // get parameter, not supported. See JCA doc
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    /**
     * <p>
     * This method is overridden by providers to initialize this signature engine
     * with the specified parameter set.
     *
     * @param params
     *            the parameters
     *
     * @exception UnsupportedOperationException
     *                if this method is not overridden by a provider
     *
     * @exception InvalidAlgorithmParameterException
     *                if this method is overridden by a provider and the given
     *                parameters are inappropriate for this signature engine
     */

    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        //System.out.println("engineSetParamter called\n");
        this.pssParameterSpec = validateSigParams(params);
        if (!(params instanceof PSSParameterSpec)) {
            throw new InvalidAlgorithmParameterException();
        }

        //Thread.dumpStack();
        pssParameterSpec = validateSigParams(params);
        MGF1ParameterSpec mgf1ParamSpec = (MGF1ParameterSpec) pssParameterSpec.getMGFParameters();

        // If the message digest specified within the params is not the same as the MGF message digest
        // then throw an InvalidAlgorithmParameterException.
        String messageDigest = pssParameterSpec.getDigestAlgorithm();
        if ((messageDigest != null) && (mgf1ParamSpec != null)) {
            String mgfMessageDigest = mgf1ParamSpec.getDigestAlgorithm();

            if (mgfMessageDigest != null) {
                boolean throwException = true;
                if ((messageDigest.equalsIgnoreCase("SHA1")
                        || messageDigest.equalsIgnoreCase("SHA-1")
                        || messageDigest.equalsIgnoreCase("SHA")) && (!provider.isFIPS())) {
                    if (mgfMessageDigest.equalsIgnoreCase("SHA1")
                            || mgfMessageDigest.equalsIgnoreCase("SHA-1")
                            || mgfMessageDigest.equalsIgnoreCase("SHA")) {
                        throwException = false;
                    }
                } else if (messageDigest.equalsIgnoreCase("SHA224")
                        || messageDigest.equalsIgnoreCase("SHA-224")) {
                    if (mgfMessageDigest.equalsIgnoreCase("SHA224")
                            || mgfMessageDigest.equalsIgnoreCase("SHA-224")) {
                        throwException = false;
                    }
                } else if (messageDigest.equalsIgnoreCase("SHA256")
                        || messageDigest.equalsIgnoreCase("SHA-256")
                        || messageDigest.equalsIgnoreCase("SHA2")) {
                    if (mgfMessageDigest.equalsIgnoreCase("SHA256")
                            || mgfMessageDigest.equalsIgnoreCase("SHA-256")
                            || mgfMessageDigest.equalsIgnoreCase("SHA2")) {
                        throwException = false;
                    }
                } else if (messageDigest.equalsIgnoreCase("SHA384")
                        || messageDigest.equalsIgnoreCase("SHA-384")
                        || messageDigest.equalsIgnoreCase("SHA3")) {
                    if (mgfMessageDigest.equalsIgnoreCase("SHA384")
                            || mgfMessageDigest.equalsIgnoreCase("SHA-384")
                            || mgfMessageDigest.equalsIgnoreCase("SHA3")) {
                        throwException = false;
                    }
                } else if (messageDigest.equalsIgnoreCase("SHA512")
                        || messageDigest.equalsIgnoreCase("SHA-512")
                        || messageDigest.equalsIgnoreCase("SHA5")) {
                    if (mgfMessageDigest.equalsIgnoreCase("SHA512")
                            || mgfMessageDigest.equalsIgnoreCase("SHA-512")
                            || mgfMessageDigest.equalsIgnoreCase("SHA5")) {
                        throwException = false;
                    }
                } else if (messageDigest.equalsIgnoreCase("SHA512/224")
                        || messageDigest.equalsIgnoreCase("SHA-512/224")) {
                    if (mgfMessageDigest.equalsIgnoreCase("SHA512/224")
                            || mgfMessageDigest.equalsIgnoreCase("SHA-512/224")) {
                        throwException = false;
                    }
                } else if (messageDigest.equalsIgnoreCase("SHA512/256")
                        || messageDigest.equalsIgnoreCase("SHA-512/256")) {
                    if (mgfMessageDigest.equalsIgnoreCase("SHA512/256")
                            || mgfMessageDigest.equalsIgnoreCase("SHA-512/256")) {
                        throwException = false;
                    }
                }

                // No need to check other messageDigest Strings since
                // mgfMessageDigest can only assume values of SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512, or variations those.
                /*
                 * According to [PKCS#1v2.1] the mask generation function (MGF) 
                 * if based on a hash algo is recommended to use the same hash 
                 * function as the hash function fingerprinting the message. 
                 * 
                 * However the structures in [PKCS#1v2.1] allow for separate 
                 * parameterization of the MGF and the message digest.
                 * 
                 * https://datatracker.ietf.org/doc/html/rfc3447#page-29
                 */
                if (throwException) {
                    InvalidAlgorithmParameterException ex = new InvalidAlgorithmParameterException(
                            "The message digest within the PSSParameterSpec does not match the MGF message digest.");
                    throw ex;
                }
            }
        }


        this.signature.setParameter(pssParameterSpec.getDigestAlgorithm(),
                pssParameterSpec.getSaltLength(), pssParameterSpec.getTrailerField(),
                pssParameterSpec.getMGFAlgorithm(), mgf1ParamSpec.getDigestAlgorithm());

    }

    protected AlgorithmParameters engineGetParameters() throws InvalidParameterException {
        AlgorithmParameters params = null;

        if (this.pssParameterSpec != null) {
            try {
                params = AlgorithmParameters.getInstance("RSASSA-PSS", provider);
                params.init(this.pssParameterSpec);
            } catch (GeneralSecurityException gse) {
                throw new ProviderException(gse.getMessage());
            }
        }

        if (pssParameterSpec == null)
            return null;

        return params;
    }

    /**
     * Utility function to convert bytes to Hex (used for debugging only)
     *
     * @param data
     * @return
     */

    String toHex(byte[] data) {

        String digits = "0123456789abcdef";
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    /**
     * Utility method for checking key length against digest length and
     * salt length
     */
    private static void checkKeyLength(RSAKey key, int digestLen, int saltLen)
            throws SignatureException {
        if (key != null) {
            int keyLength = getKeyLengthInBits(key) >> 3;
            int minLength = Math.addExact(Math.addExact(digestLen, saltLen), 2);
            if (keyLength < minLength) {
                throw new SignatureException("Key is too short, need min " + minLength);
            }
        }
    }


    // return the modulus length in bits
    private static int getKeyLengthInBits(RSAKey k) {
        if (k != null) {
            return k.getModulus().bitLength();
        }
        return -1;
    }

    /**
    * Validate the specified Signature PSS parameters.
    */
    private PSSParameterSpec validateSigParams(AlgorithmParameterSpec p)
            throws InvalidAlgorithmParameterException {
        if (p == null) {
            throw new InvalidAlgorithmParameterException("Parameters cannot be null");
        }
        if (!(p instanceof PSSParameterSpec)) {
            throw new InvalidAlgorithmParameterException(
                    "parameters must be type PSSParameterSpec");
        }
        // no need to validate again if same as current signature parameters
        PSSParameterSpec params = (PSSParameterSpec) p;
        if (params == this.pssParameterSpec)
            return params;

        RSAKey key = null;
        if (this.privateKey == null) {
            key = this.publicKey;
        } else {
            key = this.privateKey;
        }
        // check against keyParams if set
        if (key != null) {
            if (!isCompatible(key.getParams(), params)) {
                throw new InvalidAlgorithmParameterException(
                        "Signature parameters does not match key parameters");
            }
        }
        // now sanity check the parameter values
        if (!(params.getMGFAlgorithm().equalsIgnoreCase("MGF1"))) {
            throw new InvalidAlgorithmParameterException("Only supports MGF1");

        }
        if (params.getTrailerField() != PSSParameterSpec.TRAILER_FIELD_BC) {
            throw new InvalidAlgorithmParameterException("Only supports TrailerFieldBC(1)");

        }
        String digestAlgo = params.getDigestAlgorithm();
        // check key length again
        if (key != null) {
            try {
                int hLen = DIGEST_LENGTHS.get(digestAlgo);
                checkKeyLength(key, hLen, params.getSaltLength());
            } catch (SignatureException e) {
                throw new InvalidAlgorithmParameterException(e);
            }
        }
        return params;
    }

    private void ensureInit() throws SignatureException {
        RSAKey key = null;
        if (this.privateKey == null) {
            key = this.publicKey;
        } else {
            key = this.privateKey;
        }
        // RSAKey key = (this.privateKey == null) ? this.publicKey : this.privateKey;
        if (key == null) {
            throw new SignatureException("Missing key");
        }
        if (this.pssParameterSpec == null) {
            // Parameters are required for signature verification
            throw new SignatureException("Parameters required for RSASSA-PSS signatures");
        }
    }

    /**
    * Validate the specified RSAKey and its associated parameters against
    * internal signature parameters.
    */
    private void checkKeyIsValid(RSAKey rsaKey) throws InvalidKeyException {
        try {
            // validate key parameters
            if (!isCompatible(rsaKey.getParams(), this.pssParameterSpec)) {
                throw new InvalidKeyException("Key contains incompatible PSS parameter values");
            }
            // validate key length
            if (this.pssParameterSpec != null) {
                Integer hLen = DIGEST_LENGTHS.get(this.pssParameterSpec.getDigestAlgorithm());
                if (hLen == null) {
                    throw new ProviderException("Unsupported digest algo: "
                            + this.pssParameterSpec.getDigestAlgorithm());
                }
                checkKeyLength(rsaKey, hLen, this.pssParameterSpec.getSaltLength());
            }
            return;
        } catch (SignatureException e) {
            throw new InvalidKeyException(e);
        }
    }

    /**
         * Utility method for checking the key PSS parameters against signature
         * PSS parameters.
         * Returns false if any of the digest/MGF algorithms and trailerField
         * values does not match or if the salt length in key parameters is
         * larger than the value in signature parameters.
         */
    private static boolean isCompatible(AlgorithmParameterSpec keyParams,
            PSSParameterSpec sigParams) {
        if (keyParams == null) {
            // key with null PSS parameters means no restriction
            return true;
        }
        if (!(keyParams instanceof PSSParameterSpec)) {
            return false;
        }
        // nothing to compare yet, defer the check to when sigParams is set
        if (sigParams == null) {
            return true;
        }
        PSSParameterSpec pssKeyParams = (PSSParameterSpec) keyParams;
        // first check the salt length requirement
        if (pssKeyParams.getSaltLength() > sigParams.getSaltLength()) {
            return false;
        }

        // compare equality of the rest of fields based on DER encoding
        PSSParameterSpec keyParams2 = new PSSParameterSpec(pssKeyParams.getDigestAlgorithm(),
                pssKeyParams.getMGFAlgorithm(), pssKeyParams.getMGFParameters(),
                sigParams.getSaltLength(), pssKeyParams.getTrailerField());
        PSSParameters ap = new PSSParameters();
        // skip the JCA overhead
        try {
            ap.engineInit(keyParams2);
            byte[] encoded = ap.engineGetEncoded();
            ap.engineInit(sigParams);
            byte[] encoded2 = ap.engineGetEncoded();
            return Arrays.equals(encoded, encoded2);
        } catch (Exception e) {
            return false;
        }
    }
}
