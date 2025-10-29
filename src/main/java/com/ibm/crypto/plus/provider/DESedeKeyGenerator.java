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
import javax.crypto.spec.DESedeKeySpec;

/**
 * This class generates a Triple DES key.
 */
public final class DESedeKeyGenerator extends KeyGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private int keysize = 168;
    private SecureRandom cryptoRandom = null;

    /* Mask to check for parity adjustment */
    private static final byte[] PARITY_BIT_MASK = {(byte) 0x80, (byte) 0x40, (byte) 0x20,
            (byte) 0x10, (byte) 0x08, (byte) 0x04, (byte) 0x02};

    /**
     * Empty constructor
     */
    public DESedeKeyGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    /**
     * Generates the Triple DES key.
     *
     * @return the new Triple DES key
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(null);
        }

        byte[] rawkey = new byte[DESedeKeySpec.DES_EDE_KEY_LEN];
        if (keysize == 168) {
            // 3 intermediate keys
            cryptoRandom.nextBytes(rawkey);

            // Do parity adjustment for each intermediate key
            setParityBit(rawkey, 0);
            setParityBit(rawkey, 8);
            setParityBit(rawkey, 16);
        } else {
            // using 2 keys is not FIPS approved
            byte[] tmpkey = new byte[16];
            cryptoRandom.nextBytes(tmpkey);

            setParityBit(tmpkey, 0);
            setParityBit(tmpkey, 8);
            System.arraycopy(tmpkey, 0, rawkey, 0, tmpkey.length);

            // Copy the first 8 bytes into the last
            System.arraycopy(tmpkey, 0, rawkey, 16, 8);
            Arrays.fill(tmpkey, (byte) 0x00);
        }

        try {
            return new DESedeKey(provider, rawkey);
        } catch (InvalidKeyException e) {
            // Should never happen
            throw new ProviderException(e.getMessage());
        } finally {
            // fill keybytes with 0x00 - FIPS requirement to reset arrays that
            // got filled with random bytes from random
            Arrays.fill(rawkey, (byte) 0x00);
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
                "Triple DES key generation does not take any parameters");
    }

    /**
     * Initializes this key generator for a certain keysize, using the given
     * source of randomness.
     *
     * @param keysize
     *            the keysize. This is an algorithm-specific metric specified in
     *            number of bits. A keysize with 112 bits of entropy corresponds
     *            to a Triple DES key with 2 intermediate keys, and a keysize
     *            with 168 bits of entropy corresponds to a Triple DES key with
     *            3 intermediate keys.
     * @param random
     *            the source of randomness for this key generator
     */
    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if ((keysize != 112) && (keysize != 168)) {
            throw new InvalidParameterException("Wrong keysize: must be " + "equal to 112 or 168");
        }
        this.keysize = keysize;
        this.engineInit(random);
    }

    /*
     * Does parity adjustment, using bit in position 8 as the parity bit, for 8
     * key bytes, starting at <code>offset</code>.
     *
     * The 8 parity bits of a DES key are only used for sanity-checking of the
     * key, to see if the key could actually be a key. If you check the parity
     * of the quantity, and it winds up not having the correct parity, then
     * you'll know something went wrong.
     *
     * A key that is not parity adjusted (e.g. e4e4e4e4e4e4e4e4) produces the
     * same output as a key that is parity adjusted (e.g. e5e5e5e5e5e5e5e5),
     * because it is the 56 bits of the DES key that are cryptographically
     * significant/"effective" -- the other 8 bits are just used for parity
     * checking.
     */
    static void setParityBit(byte[] key, int offset) {
        if (key == null)
            return;

        for (int i = 0; i < 8; i++) {
            int bitCount = 0;
            for (int maskIndex = 0; maskIndex < PARITY_BIT_MASK.length; maskIndex++) {
                if ((key[i + offset] & PARITY_BIT_MASK[maskIndex]) == PARITY_BIT_MASK[maskIndex]) {
                    bitCount++;
                }
            }
            if ((bitCount & 0x01) == 1) {
                // Odd number of 1 bits in the top 7 bits. Set parity bit to 0
                key[i + offset] = (byte) (key[i + offset] & (byte) 0xfe);
            } else {
                // Even number of 1 bits in the top 7 bits. Set parity bit to 1
                key[i + offset] = (byte) (key[i + offset] | 1);
            }
        }
    }
}
