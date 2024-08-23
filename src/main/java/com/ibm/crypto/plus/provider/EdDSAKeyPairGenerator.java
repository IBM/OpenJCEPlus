/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.CurveUtil.CURVE;
import com.ibm.crypto.plus.provider.ock.XECKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

/**
 * Key pair generator for the EdDSA signature algorithm.
 */
abstract class EdDSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final NamedParameterSpec DEFAULT_PARAM_SPEC
        = NamedParameterSpec.ED25519;
    private SecureRandom random = null;
    private NamedParameterSpec namedSpec;
    private CURVE curve;
    private OpenJCEPlusProvider provider = null;

    private String alg = null;

    private EdDSAKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
        try {
            initialize(DEFAULT_PARAM_SPEC);
        } catch (Exception e) {
            throw new InvalidParameterException(e.getMessage());
        }
        
    }

    private EdDSAKeyPairGenerator(OpenJCEPlusProvider provider, String Alg) {
        this.provider = provider;
        this.alg = Alg;
        try {
            initialize(new NamedParameterSpec(Alg), null);
        } catch (Exception e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        if (keySize == 255) {
            this.namedSpec = NamedParameterSpec.ED25519;
        } else if (keySize == 448) {
            this.namedSpec = NamedParameterSpec.ED448;
        } else {
            throw new InvalidParameterException("Invalid Key size");
        }
        try {
            initialize(this.namedSpec);
        } catch (Exception e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    /**
     * Initializes generator from params, random is ignored
     *
     * @param params must be NamedParameterSpec
     * @param random ignored parameter
     * @throws InvalidAlgorithmParameterException
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        initialize(params);
    }

    public void initialize(AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        // Check if parameter is a valid NamedParameterSpec instance
        if (params instanceof NamedParameterSpec) {
            this.namedSpec = (NamedParameterSpec) params;
        } else {
            throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec: " + params);
        }

        //Validate that the parameters match the alg specified on creation of this object
        if (this.alg != null && !(this.namedSpec.getName().equals(this.alg))) {
            this.namedSpec = null;
            throw new InvalidAlgorithmParameterException("Parameters must be " + this.alg);
        }

        this.curve = CurveUtil.getCurve(this.namedSpec.getName());
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            int keySize = CurveUtil.getCurveSize(curve);
            XECKey xecKey = XECKey.generateKeyPair(provider.getOCKContext(),
                    this.curve.ordinal(), keySize);
            EdDSAPublicKeyImpl pubKey = new EdDSAPublicKeyImpl(provider, xecKey,
                    this.curve);
            EdDSAPrivateKeyImpl privKey = new EdDSAPrivateKeyImpl(provider, xecKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }

    public static final class Ed25519 extends EdDSAKeyPairGenerator {
        public Ed25519(OpenJCEPlusProvider provider) {
            super(provider, "Ed25519");
        }
    }

    ;

    public static final class Ed448 extends EdDSAKeyPairGenerator {
        public Ed448(OpenJCEPlusProvider provider) {
            super(provider, "Ed448");
        }
    }

    public static final class EdDSA extends EdDSAKeyPairGenerator {
        public EdDSA(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }

    ;
}
