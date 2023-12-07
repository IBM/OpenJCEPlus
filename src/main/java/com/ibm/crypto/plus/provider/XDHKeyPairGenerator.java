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

public class XDHKeyPairGenerator extends KeyPairGeneratorSpi {

    public static final String DEFAULT_ALGO = "X25519";
    private OpenJCEPlusProvider provider = null;
    NamedParameterSpec namedSpec;
    private String alg = null;

    // serviceCurve parameter is used to keep explicit service curve algorithm, either X25519 or X448
    private NamedParameterSpec.CURVE serviceCurve = null;

    /**
     * Creates an XDHKeyPairGenerator object and sets its provider
     *
     * @param provider
     */
    XDHKeyPairGenerator(OpenJCEPlusProvider provider) {
        initXDHKeyPairGenerator(provider, null);
    }

    /**
     * Creates an XDHKeyPairGenerator object and sets its provider and algorithm
     *
     * @param provider must be NamedParameterSpec
     * @param Alg curve algorithm
     */
    protected XDHKeyPairGenerator(OpenJCEPlusProvider provider, String Alg) {
        initXDHKeyPairGenerator(provider, new NamedParameterSpec(Alg));
    }

    /**
     * Creates an XDHKeyPairGenerator object and sets its provider and parameters.
     * It is called from sub-class to set up X25519 or X448 service
     *
     * @param provider
     * @param params
     */
    protected XDHKeyPairGenerator(OpenJCEPlusProvider provider, NamedParameterSpec params) {
        initXDHKeyPairGenerator(provider, params);
    }

    private void initXDHKeyPairGenerator(OpenJCEPlusProvider provider, NamedParameterSpec params) {
        this.provider = provider;
        try {
            if (params == null) {
                // Default Initialization is X25519.
                // Default init of namedSpec is replaced when initialize is called directly.
                initialize(new NamedParameterSpec(DEFAULT_ALGO), null);
            } else {
                initialize(params, null);
                this.alg = params.getName();
                serviceCurve = params.getCurve();
            }
        } catch (InvalidAlgorithmParameterException e) {
            throw provider.providerException("Failure in XDHKeyPairGenerator: ", e);
        }
    }

    /**
     * Initializes generator from keySize, random is ignored
     *
     * @param keySize
     * @param random  ignored parameter
     * @throws InvalidParameterException
     */
    @Override
    public void initialize(int keySize, SecureRandom random) {
        initializeImpl(new NamedParameterSpec(keySize));
    }

    /**
     * Initializes generator from params, random is ignored
     *
     * @param params
     * @param random ignored parameter
     * @throws InvalidAlgorithmParameterException
     */
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        NamedParameterSpec nps = null;
        try {
            // get the internal wrapper instance from input params
            nps = NamedParameterSpec.getInternalNamedParameterSpec(params);
        } catch (InvalidParameterException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage());
        }
        initializeImpl(nps);
    }

    /**
     * Initializes generator from params
     *
     * @param params
     * @throws InvalidAlgorithmParameterException
     */
    private void initializeImpl(NamedParameterSpec params) {
        //Validate that the parameters match the alg specified on creation of this object
        if (this.alg != null && !params.getName().equals(this.alg)) {
            namedSpec = null;
            throw new InvalidParameterException("Parameters must be " + this.alg);
        }

        // Check if service is instantiated explicitly for a specific curve algorithm, X25519 or X448
        if (serviceCurve != null && serviceCurve != params.getCurve()) {
            throw new InvalidParameterException("Params must be: " + serviceCurve.toString());
        }
        namedSpec = params;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (this.alg != null && namedSpec == null) {
            namedSpec = new NamedParameterSpec(this.alg);
        } else if (namedSpec == null) {
            namedSpec = new NamedParameterSpec(DEFAULT_ALGO);
        }
        try {
            XECKey xecKey = XECKey.generateKeyPair(provider.getOCKContext(), namedSpec.getCurve());
            XDHPrivateKeyImpl privKey = new XDHPrivateKeyImpl(provider, xecKey);
            XDHPublicKeyImpl pubKey = new XDHPublicKeyImpl(provider, xecKey, namedSpec.getCurve());
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }

    }

    public static final class X25519 extends XDHKeyPairGenerator {

        public X25519(OpenJCEPlusProvider provider) {
            super(provider, new NamedParameterSpec(NamedParameterSpec.CURVE.X25519));
        }
    }

    public static final class X448 extends XDHKeyPairGenerator {

        public X448(OpenJCEPlusProvider provider) {
            super(provider, new NamedParameterSpec(NamedParameterSpec.CURVE.X448));
        }
    }

    public static final class XDH extends XDHKeyPairGenerator {
        public XDH(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }
}
