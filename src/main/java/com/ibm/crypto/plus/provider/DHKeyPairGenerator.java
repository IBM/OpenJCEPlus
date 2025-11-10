/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.DHKey;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.DHParameterSpec;

public final class DHKeyPairGenerator extends KeyPairGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private int keySize = 2048;
    private DHParameterSpec params;

    public DHKeyPairGenerator(OpenJCEPlusProvider provider) {
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
    @Override
    public void initialize(int keySize, SecureRandom random) throws InvalidParameterException {

        initialize(keySize, true, random);
    }

    /**
     * Initializes the key pair generator for a given modulus length, without
     * parameters.
     *
     * @param keySize
     *            int the modulus length, in bits. Valid values are any multiple
     *            of 8 between 512 and 8192, inclusive.
     * @param genParams
     *            boolean whether or not to generate new parameters for the
     *            modulus length requested.
     * @param random
     *            SecureRandom the random bit source to use to generate key
     *            bits.
     *
     */
    private void initialize(int keySize, boolean genParams, java.security.SecureRandom random) {

        DHUtils.checkKeySize(keySize, 0, provider.isFIPS());

        if (genParams) {
            // Use the built-in parameters (ranging from 512 to 8192)
            // when available.

            boolean supported = ((keySize == 2048) || (keySize == 3072) || (keySize == 4096)
                    || (keySize == 6144) || (keySize == 8192)
                    || ((keySize >= 512) && (keySize <= 1024) && ((keySize & 0x3F) == 0)));

            if (!supported) {
                throw new InvalidParameterException("DH key size must be multiple of 64 and range "
                        + "from 512 to 1024 (inclusive), or 2048, 3072 or 4096 or 6144 or 8192 "
                        + "The specific key size " + keySize + " is not supported");
            }
            this.params = null;
        } else {
            this.params = DHParameterGenerator.getPrecomputedParameters(this.keySize);
            if (this.params == null) {
                throw new InvalidParameterException(
                        "No precomputed parameters for requested modulus size available");
            }
        }
        this.keySize = keySize;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException, InvalidParameterException {
        if (params instanceof DHParameterSpec == false) {
            throw new InvalidAlgorithmParameterException("Inappropriate parameter");
        }

        initialize((DHParameterSpec) params, random);
    }

    private void initialize(DHParameterSpec params, java.security.SecureRandom random)
            throws InvalidParameterException {
        int keySize = params.getP().bitLength();
        DHUtils.checkKeySize(keySize, params.getL(), provider.isFIPS());
        this.keySize = keySize;
        this.params = params;
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            DHKey dhKey;

            if (params == null) {
                params = DHParameterGenerator.getPrecomputedParameters(this.keySize);
            }

            if (params == null) {
                boolean supported = ((keySize == 2048) || (this.keySize == 3072)
                        || (keySize == 4096) || (keySize == 6144) || (keySize == 8192)
                        || ((keySize >= 512) && (keySize <= 1024) && ((keySize & 0x3F) == 0)));

                if (!supported) {
                    throw new InvalidParameterException(
                            "DH key size must be multiple of 64 and range "
                                    + "from 512 to 1024 (inclusive), or 2048, 3072 or 4096 or 6144 or 8192 "
                                    + "The specific key size " + keySize + " is not supported");
                }
                AlgorithmParameterGenerator algParmGen = AlgorithmParameterGenerator
                        .getInstance("DH", provider);
                algParmGen.init(this.keySize);
                AlgorithmParameters algParams = algParmGen.generateParameters();
                this.params = algParams.getParameterSpec(DHParameterSpec.class);

                dhKey = DHKey.generateKeyPair(provider.getOCKContext(), algParams.getEncoded(), provider);
            } else {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance("DH", provider);
                algParams.init(params);

                dhKey = DHKey.generateKeyPair(provider.getOCKContext(), algParams.getEncoded(), provider);
            }

            javax.crypto.interfaces.DHPrivateKey privKey = new DHPrivateKey(provider, dhKey);
            javax.crypto.interfaces.DHPublicKey pubKey = new DHPublicKey(provider, dhKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }
}
