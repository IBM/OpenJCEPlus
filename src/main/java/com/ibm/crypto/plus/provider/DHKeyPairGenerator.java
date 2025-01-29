/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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

    public final static int MIN_KEYSIZE_NONFIPS = 512;
    public final static int MAX_KEYSIZE_NONFIPS = 8192;
    public final static int MIN_KEYSIZE_FIPS = 2048;
    public final static int MAX_KEYSIZE_FIPS = 8192;

    public DHKeyPairGenerator(OpenJCEPlusProvider provider) {

        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

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

        if (provider.isFIPS()) {
            checkKeySize(keySize, MIN_KEYSIZE_FIPS, MAX_KEYSIZE_FIPS, 0);
        } else {
            checkKeySize(keySize, MIN_KEYSIZE_NONFIPS, MAX_KEYSIZE_NONFIPS, 0);
        }

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
        if (provider.isFIPS()) {
            checkKeySize(keySize, MIN_KEYSIZE_FIPS, MAX_KEYSIZE_FIPS, params.getL());
        } else {
            checkKeySize(keySize, MIN_KEYSIZE_NONFIPS, MAX_KEYSIZE_NONFIPS, params.getL());
        }
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

                dhKey = DHKey.generateKeyPair(provider.getOCKContext(), algParams.getEncoded());
            } else {
                AlgorithmParameters algParams = AlgorithmParameters.getInstance("DH", provider);
                algParams.init(params);

                dhKey = DHKey.generateKeyPair(provider.getOCKContext(), algParams.getEncoded());
            }

            javax.crypto.interfaces.DHPrivateKey privKey = new DHPrivateKey(provider, dhKey);
            javax.crypto.interfaces.DHPublicKey pubKey = new DHPublicKey(provider, dhKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }

    /**
     * Check the length of an DH key modulus/exponent to make sure it is not
     * too short or long. Some impls have their own min and max key sizes that
     * may or may not match with a system defined value.
     *
     * @param keySize
     *                the bit length of the modulus.
     * @param minSize
     *                the minimum length of the modulus.
     * @param maxSize
     *                the maximum length of the modulus.
     * @param expSize
     *                the bit length of the exponent.
     *
     * @throws InvalidParameterException
     *                             if any of the values are unacceptable.
     */
    static void checkKeySize(int keySize, int minSize, int maxSize, int expSize)
            throws InvalidParameterException {

        if ((keySize < minSize) || (keySize > maxSize) || ((keySize & 0x3F) != 0)) {
            throw new InvalidParameterException(
                    "DH key size must be multiple of 64, and can only range " +
                            "from " + minSize + " to " + maxSize + " (inclusive). " +
                            "The specific key size " + keySize + " is not supported");
        }

        // optional, could be 0 if not specified
        if ((expSize < 0) || (expSize > keySize)) {
            throw new InvalidParameterException("Exponent size must be positive and no larger than" +
                    " modulus size");
        }
    }

}
