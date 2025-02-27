/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.RSAUtil.KeyType;
import com.ibm.crypto.plus.provider.ock.Signature;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.List;

abstract class RSASignature extends SignatureSpi {

    private OpenJCEPlusProvider provider = null;
    private Signature signature = null;
    private String ockDigestAlgo = null;
    java.security.PublicKey publicKey = null;
    java.security.PrivateKey privateKey = null;

    RSASignature(OpenJCEPlusProvider provider, String ockDigestAlgo) {
        try {
            this.provider = provider;
            this.ockDigestAlgo = ockDigestAlgo;
            this.signature = Signature.getInstance(provider.getOCKContext(), ockDigestAlgo);
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize RSA signature", e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {

        this.privateKey = null;
        this.publicKey = publicKey;
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey)) {
            throw new InvalidKeyException("Key is not an RSAPublicKey");
        }

        List<Integer> specificModulesLen = null;
        int minModulusLen = RSAKeyFactory.MIN_MODLEN_NONFIPS;
        if (provider.isFIPS()) {
            minModulusLen = RSAKeyFactory.MIN_MODLEN_FIPS_PUB;
            specificModulesLen = RSAKeyFactory.ALLOWABLE_MODLEN_FIPS_VERIFY;
        }
        RSAKeyFactory.checkKeyLengths(((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength(),
                                        RSAKeyGenParameterSpec.F4,
                                        minModulusLen,
                                        64 * 1024,
                                        specificModulesLen,
                                        "verify");

        RSAPublicKey rsaPublic = (RSAPublicKey) RSAKeyFactory.toRSAKey(provider, publicKey);
        try {
            RSAUtil.checkParamsAgainstType(KeyType.RSA, rsaPublic.getParams());
        } catch (ProviderException e) {
            throw new InvalidKeyException("Invalid key for RSA signatures", e);
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
            this.signature.initialize(rsaPublic.getOCKKey(), false);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInitVerify", e);
        }
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.privateKey = privateKey;
        this.publicKey = null;

        if (!(privateKey instanceof java.security.interfaces.RSAPrivateKey)) {
            throw new InvalidKeyException("Key is not an RSAPrivateKey");
        }

        List<Integer> specificModulesLen = null;
        int minModulusLen = RSAKeyFactory.MIN_MODLEN_NONFIPS;
        if (provider.isFIPS()) {
            minModulusLen = RSAKeyFactory.MIN_MODLEN_FIPS;
            specificModulesLen = RSAKeyFactory.ALLOWABLE_MODLEN_FIPS_SIGN;
        }
        RSAKeyFactory.checkKeyLengths(((java.security.interfaces.RSAPrivateKey) privateKey).getModulus().bitLength(),
                                        RSAKeyGenParameterSpec.F4,
                                        minModulusLen,
                                        64 * 1024,
                                        specificModulesLen,
                                        "sign");

        //RSAPrivateCrtKey rsaPrivate = (RSAPrivateCrtKey) RSAKeyFactory.toRSAKey(provider, privateKey);
        PrivateKey rsaPrivate = (PrivateKey) RSAKeyFactory.toRSAKey(provider, privateKey);

        try {
            if (rsaPrivate instanceof RSAPrivateCrtKey) {
                RSAUtil.checkParamsAgainstType(KeyType.RSA,
                        ((RSAPrivateCrtKey) rsaPrivate).getParams());
            } else if (rsaPrivate instanceof RSAPrivateKey) {
                RSAUtil.checkParamsAgainstType(KeyType.RSA,
                        ((RSAPrivateKey) rsaPrivate).getParams());
            }

        } catch (ProviderException e) {
            throw new InvalidKeyException("Invalid key for RSA signatures", e);
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
                this.signature.initialize(((RSAPrivateCrtKey) rsaPrivate).getOCKKey(), false);
            } else if (rsaPrivate instanceof RSAPrivateKey) {
                this.signature.initialize(((RSAPrivateKey) rsaPrivate).getOCKKey(), true);
            }
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

    // See JCA doc
    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("No parameters accepted");
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (this.privateKey == null) {
            throw new SignatureException("Missing private key");
        }
        try {
            if (this.provider.toString().contains("FIPS") && this.ockDigestAlgo.contains("SHA1")) {
                throw new SignatureException("FIPS does not support signing SHA1WithRSA");
            }
            return this.signature.sign();
        } catch (Exception e) {
            SignatureException signatureException = new SignatureException("Could not sign data");
            provider.setOCKExceptionCause(signatureException, e);
            throw signatureException;
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("Missing public key");
        }
        try {
            return this.signature.verify(sigBytes);
        } catch (Exception e) {
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

    public static final class SHA1withRSA extends RSASignature {
        public SHA1withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA1"); // OCK digest name
        }
    }

    public static final class SHA224withRSA extends RSASignature {
        public SHA224withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA224"); // OCK digest name
        }
    }

    public static final class SHA256withRSA extends RSASignature {
        public SHA256withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA256"); // OCK digest name
        }
    }

    public static final class SHA384withRSA extends RSASignature {
        public SHA384withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA384"); // OCK digest name
        }
    }

    public static final class SHA512withRSA extends RSASignature {
        public SHA512withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA512"); // OCK digest name
        }
    }

    public static final class SHA3_224withRSA extends RSASignature {
        public SHA3_224withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-224"); // OCK digest name
        }
    }

    public static final class SHA3_256withRSA extends RSASignature {
        public SHA3_256withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-256"); // OCK digest name
        }
    }

    public static final class SHA3_384withRSA extends RSASignature {
        public SHA3_384withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-384"); // OCK digest name
        }
    }

    public static final class SHA3_512withRSA extends RSASignature {
        public SHA3_512withRSA(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-512"); // OCK digest name
        }
    }
}
