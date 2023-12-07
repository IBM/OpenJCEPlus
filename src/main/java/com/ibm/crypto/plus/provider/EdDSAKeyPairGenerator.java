/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import com.ibm.crypto.plus.provider.ock.XECKey;
import ibm.security.internal.spec.NamedParameterSpec;

/**
 * Key pair generator for the EdDSA signature algorithm.
 */
public class EdDSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private SecureRandom random = null;
    private NamedParameterSpec namedSpec;
    private OpenJCEPlusProvider provider = null;

    private String alg = null;

    public EdDSAKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    public EdDSAKeyPairGenerator(OpenJCEPlusProvider provider, String Alg) {
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
            this.namedSpec = new NamedParameterSpec("Ed25519");
            if (this.alg == null) {
                this.alg = "Ed25519";
            }
        } else if (keySize == 448) {
            this.namedSpec = new NamedParameterSpec("Ed448");
            if (this.alg == null) {
                this.alg = "Ed448";
            }
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
        try {
            this.namedSpec = NamedParameterSpec.getInternalNamedParameterSpec(params);
        } catch (InvalidParameterException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }

        //Validate that the parameters match the alg specified on creation of this object
        if (this.alg != null && !(this.namedSpec.getName().equals(this.alg))) {
            this.namedSpec = null;
            throw new InvalidAlgorithmParameterException("Parameters must be " + this.alg);
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        if (this.alg != null && this.namedSpec == null) {
            this.namedSpec = new NamedParameterSpec(this.alg);
        } else if (namedSpec == null) {
            this.namedSpec = new NamedParameterSpec("Ed25519");
        }
        try {
            XECKey xecKey = XECKey.generateKeyPair(provider.getOCKContext(),
                    this.namedSpec.getCurve());
            EdDSAPublicKeyImpl pubKey = new EdDSAPublicKeyImpl(provider, xecKey,
                    this.namedSpec.getCurve());
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

    ;

    public static final class EdDSA extends EdDSAKeyPairGenerator {
        public EdDSA(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }

    ;
}
