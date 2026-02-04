/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.DSAKey;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;

/**
 * This class is a concrete implementation for the generation of a pair of DSA
 * keys
 */
public final class DSAKeyPairGenerator extends KeyPairGenerator
        implements java.security.interfaces.DSAKeyPairGenerator {
    private OpenJCEPlusProvider provider = null;
    private int keySize = 2048;
    private DSAParameterSpec params;

    public DSAKeyPairGenerator(OpenJCEPlusProvider provider) {
        super("DSA");
        this.provider = provider;
        initialize(2048, null);
    }

    /**
     * Initialize the receiver to use a given secure random generator, and
     * generate keys of a certain size.
     *
     * @param keySize
     *            int New size of keys, in bits
     * @param random
     *            SecureRandom New secure random to use
     */
    public void initialize(int keySize, SecureRandom random) {
        initialize(keySize, true, random);
    }

    /**
     * Initializes the key pair generator for a given modulus length, without
     * parameters.
     *
     * @param modlen
     *            int the modulus length, in bits. Valid values are any multiple
     *            of 8 between 512 and 1024, inclusive.
     * @param genParams
     *            boolean whether or not to generate new parameters for the
     *            modulus length requested.
     * @param random
     *            SecureRandom the random bit source to use to generate key
     *            bits.
     *
     */
    public void initialize(int modlen, boolean genParams, java.security.SecureRandom random) {
        int subPrimeLen = DSAKeyFactory.getDefaultSubprimeLen(modlen);

        try {
            DSAKeyFactory.checkStrength(provider, modlen, subPrimeLen);
        } catch (InvalidKeyException e) {
            throw new InvalidParameterException(e.getMessage());
        }

        if (genParams) {
            this.params = null;
        } else {
            this.params = DSAParameterGenerator.getPrecomputedParameters(this.keySize, provider);
            if (this.params == null) {
                throw new InvalidParameterException(
                        "No precomputed parameters for requested modulus size available");
            }
        }
        this.keySize = modlen;
    }

    /**
     * Initializes the key pair generator using p, q and g, the DSA family
     * parameters.
     *
     * @param params
     *            DSAParams the parameters to use to generate the keys.
     * @param random
     *            SecureRandom the random bit source to use to generate key
     *            bits.
     *
     */
    public void initialize(DSAParams params, java.security.SecureRandom random) {
        if (params == null) {
            throw new InvalidParameterException("Params must not be null");
        }

        DSAParameterSpec spec = new DSAParameterSpec(params.getP(), params.getQ(), params.getG());

        initialize(spec, random);
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof DSAParameterSpec == false) {
            throw new InvalidAlgorithmParameterException("Inappropriate parameter");
        }

        initialize((DSAParameterSpec) params, random);
    }

    private void initialize(DSAParameterSpec params, java.security.SecureRandom random) {
        int sizeP = params.getP().bitLength();
        int sizeQ = params.getQ().bitLength();

        try {
            DSAKeyFactory.checkStrength(provider, sizeP, sizeQ);
        } catch (InvalidKeyException e) {
            throw new InvalidParameterException(e.getMessage());
        }

        this.keySize = sizeP;
        this.params = params;
    }

    public KeyPair generateKeyPair() {
        try {
            DSAKey dsaKey;

            if (params == null) {
                params = DSAParameterGenerator.getPrecomputedParameters(this.keySize, provider);
            }

            if (params == null) {
                AlgorithmParameterGenerator algParmGen = AlgorithmParameterGenerator
                        .getInstance("DSA", provider);
                algParmGen.init(this.keySize);
                AlgorithmParameters algParams = algParmGen.generateParameters();
                this.params = algParams.getParameterSpec(DSAParameterSpec.class);

                dsaKey = DSAKey.generateKeyPair(provider.getOCKContext(), algParams.getEncoded(), provider);
            } else {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance("DSA", provider);
                algParams.init(params);

                dsaKey = DSAKey.generateKeyPair(provider.getOCKContext(), algParams.getEncoded(), provider);
            }

            java.security.interfaces.DSAPrivateKey privKey = new DSAPrivateKey(provider, dsaKey);
            java.security.interfaces.DSAPublicKey pubKey = new DSAPublicKey(provider, dsaKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }
}
