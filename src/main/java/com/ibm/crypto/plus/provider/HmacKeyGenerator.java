/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

abstract class HmacKeyGenerator extends KeyGeneratorSpi {

    private OpenJCEPlusProvider provider;
    private final String algo;
    private int keysize;
    private SecureRandom cryptoRandom = null;

    HmacKeyGenerator(OpenJCEPlusProvider provider, String algo, int keysize) {
        this.provider = provider;
        this.algo = algo;
        this.keysize = keysize; // default keysize in bytes
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(null);
        }

        byte[] keyBytes = new byte[this.keysize];
        cryptoRandom.nextBytes(keyBytes);

        try {
            return new SecretKeySpec(keyBytes, algo);
        } finally {
            // fill keybytes with 0x00 - FIPS requirement to reset arrays that
            // got filled with random bytes from random
            Arrays.fill(keyBytes, (byte) 0x00);
        }
    }

    @Override
    protected void engineInit(SecureRandom random) {
        // If in FIPS mode, SecureRandom must be internal and FIPS approved.
        // For FIPS mode, user provided random generator will be ignored.
        //
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                algo + " key generation does not take any parameters");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        this.keysize = (keysize + 7) / 8;
        this.engineInit(random);
    }

    // nested static class for the HmacMD5 KeyGenerator implementation
    public static final class HmacMD5 extends HmacKeyGenerator {
        public HmacMD5(OpenJCEPlusProvider provider) {
            super(provider, "HmacMD5", 64);
        }
    }

    // nested static class for the HmacSHA1 KeyGenerator implementation
    public static final class HmacSHA1 extends HmacKeyGenerator {
        public HmacSHA1(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA1", 64);
        }
    }

    // nested static class for the HmacSHA224 KeyGenerator implementation
    public static final class HmacSHA224 extends HmacKeyGenerator {
        public HmacSHA224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA224", 64);
        }
    }

    // nested static class for the HmacSHA256 KeyGenerator implementation
    public static final class HmacSHA256 extends HmacKeyGenerator {
        public HmacSHA256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA256", 64);
        }
    }

    // nested static class for the HmacSHA384 KeyGenerator implementation
    public static final class HmacSHA384 extends HmacKeyGenerator {
        public HmacSHA384(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA384", 128);
        }
    }

    // nested static class for the HmacSHA512 KeyGenerator implementation
    public static final class HmacSHA512 extends HmacKeyGenerator {
        public HmacSHA512(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA512", 128);
        }
    }

    // nested static class for the HmacSHA3_224 KeyGenerator implementation
    public static final class HmacSHA3_224 extends HmacKeyGenerator {
        public HmacSHA3_224(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-224", 64);
        }
    }

    // nested static class for the HmacSHA3_256 KeyGenerator implementation
    public static final class HmacSHA3_256 extends HmacKeyGenerator {
        public HmacSHA3_256(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-256", 64);
        }
    }

    // nested static class for the HmacSHA3_384 KeyGenerator implementation
    public static final class HmacSHA3_384 extends HmacKeyGenerator {
        public HmacSHA3_384(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-384", 128);
        }
    }

    // nested static class for the HmacSHA3_512 KeyGenerator implementation
    public static final class HmacSHA3_512 extends HmacKeyGenerator {
        public HmacSHA3_512(OpenJCEPlusProvider provider) {
            super(provider, "HmacSHA3-512", 128);
        }
    }
}
