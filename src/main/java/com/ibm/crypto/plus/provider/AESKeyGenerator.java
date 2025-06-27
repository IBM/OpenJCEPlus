/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * This class generates a secret key for use with the AES algorithm.
 */
public final class AESKeyGenerator extends KeyGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private int keysize = 16; // default keysize (in bytes)
    private SecureRandom cryptoRandom = null;

    /**
     * Empty constructor
     */
    public AESKeyGenerator(OpenJCEPlusProvider provider) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

        this.provider = provider;
    }

    /**
     * Generates an AES key.
     *
     * @return the new AES key
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(null);
        }

        byte[] keyBytes = new byte[this.keysize];
        cryptoRandom.nextBytes(keyBytes);

        try {
            return new AESKey(provider, keyBytes);
        } catch (InvalidKeyException e) {
            // Should never happen
            throw new ProviderException(e.getMessage());
        } finally {
            // fill keybytes with 0x00 - FIPS requirement to reset arrays that
            // got filled with random bytes from random
            Arrays.fill(keyBytes, (byte) 0x00);
        }
    }

    /**
     * Initializes this key generator.
     * 
     * @param random
     *            the source of randomness for this generator
     */
    @Override
    protected void engineInit(SecureRandom random) {
        // If in FIPS mode, SecureRandom must be internal and FIPS approved.
        // For FIPS mode, user provided random generator will be ignored.
        //
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
    }

    /**
     * Initializes this key generator with the specified parameter set and a
     * user-provided source of randomness.
     *
     * @param params
     *            the key generation parameters
     * @param random
     *            the source of randomness for this key generator
     *
     * @exception InvalidAlgorithmParameterException
     *                if <code>params</code> is inappropriate for this key
     *                generator
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "AES key generation does not take any parameters");
    }

    /**
     * Initializes this key generator for a certain keysize, using the given
     * source of randomness.
     *
     * @param keysize
     *            the keysize. This is an algorithm-specific metric specified in
     *            number of bits.
     * @param random
     *            the source of randomness for this key generator
     */
    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (((keysize % 8) != 0) || (!AESUtils.isKeySizeValid(keysize / 8))) {
            throw new InvalidParameterException("Wrong keysize: must be equal to 128, 192 or 256");
        }

        this.keysize = keysize / 8;
        this.engineInit(random);
    }
}
