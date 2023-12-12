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
import java.security.spec.NamedParameterSpec;

import com.ibm.crypto.plus.provider.ock.XECKey;

public class XDHKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final NamedParameterSpec DEFAULT_PARAM_SPEC
        = NamedParameterSpec.X25519;
    private OpenJCEPlusProvider provider = null;
    private NamedParameterSpec namedSpec;
    private String alg = null;

    // serviceCurve parameter is used to keep explicit service curve algorithm, either X25519 or X448
    private CurveUtil.CURVE serviceCurve = null;

    /**
     * Creates an XDHKeyPairGenerator object and sets its provider
     *
     * @param provider
     */
    XDHKeyPairGenerator(OpenJCEPlusProvider provider) {
        initXDHKeyPairGenerator(provider, null);
    }

    /**
     * Creates an XDHKeyPairGenerator object and sets its provider and parameters.
     * It is called from sub-class to set up X25519 or X448 service
     *
     * @param provider
     * @param params
     */
    private XDHKeyPairGenerator(OpenJCEPlusProvider provider, NamedParameterSpec params) {
        initXDHKeyPairGenerator(provider, params);
    }

    private void initXDHKeyPairGenerator(OpenJCEPlusProvider provider, NamedParameterSpec params) {
        this.provider = provider;
        try {
            if (params == null) {
                // Default Initialization is X25519.
                // Default init of namedSpec is replaced when initialize is called directly.
                initialize(DEFAULT_PARAM_SPEC, null);
            } else {
                initialize(params, null);
                this.alg = params.getName();
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
        CurveUtil.CURVE curve = CurveUtil.getCurveOfSize(keySize);
        initializeImpl(new NamedParameterSpec(curve.name()));
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
        
        if (params instanceof NamedParameterSpec) {
            nps = (NamedParameterSpec) params;
        } else {
            throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec: " + params);
        }
        
        initializeImpl(nps);
    }

    /**
     * Initializes generator from params
     *
     * @param params
     * @throws InvalidParameterException
     */
    private void initializeImpl(NamedParameterSpec params) {
        //Validate that the parameters match the alg specified on creation of this object
        if (this.alg != null && !params.getName().equals(this.alg)) {
            namedSpec = null;
            throw new InvalidParameterException("Parameters must be " + this.alg);
        }

        serviceCurve = CurveUtil.getCurve(params.getName());
        namedSpec = params;
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            int pub_size = CurveUtil.getPublicCurveSize(serviceCurve);
            XECKey xecKey = XECKey.generateKeyPair(provider.getOCKContext(), this.serviceCurve.ordinal(), pub_size);
            XDHPrivateKeyImpl privKey = new XDHPrivateKeyImpl(provider, xecKey);
            XDHPublicKeyImpl pubKey = new XDHPublicKeyImpl(provider, xecKey, this.serviceCurve);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }

    }

    public static final class X25519 extends XDHKeyPairGenerator {

        public X25519(OpenJCEPlusProvider provider) {
            super(provider, new NamedParameterSpec(CurveUtil.CURVE.X25519.name()));
        }
    }

    public static final class X448 extends XDHKeyPairGenerator {

        public X448(OpenJCEPlusProvider provider) {
            super(provider, new NamedParameterSpec(CurveUtil.CURVE.X448.name()));
        }
    }

    public static final class XDH extends XDHKeyPairGenerator {
        public XDH(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }
}
