/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * KeyGenerator implementation for the SSL/TLS RSA premaster secret.
 */
public final class TlsRsaPremasterSecretGenerator extends KeyGeneratorSpi {

    private final static String MSG = "TlsRsaPremasterSecretGenerator must be "
            + "initialized using a TlsRsaPremasterSecretParameterSpec";

    private OpenJCEPlusProvider provider = null;
    private sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec spec;
    private SecureRandom random;

    public TlsRsaPremasterSecretGenerator(OpenJCEPlusProvider provider) {

        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

        this.provider = provider;
    }

    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec == false) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec) params;
        this.random = random;
    }

    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    protected SecretKey engineGenerateKey() {
        if (spec == null) {
            throw new IllegalStateException("TlsRsaPremasterSecretGenerator must be initialized");
        }

        byte[] b = spec.getEncodedSecret();
        if (b == null) {
            if (random == null) {
                // If a SecureRandom object was not provided, then use FIPS
                // approved SecureRandom to be SP800-131a compliant.
                //
                random = provider.getSecureRandom(null);
            }

            b = new byte[48];
            random.nextBytes(b);
            b[0] = (byte) spec.getMajorVersion();
            b[1] = (byte) spec.getMinorVersion();
        }
        SecretKey sKey = new SecretKeySpec(b, "TlsRsaPremasterSecret");
        // fill b with 0x00 - FIPS requirement to reset arrays that
        // got filled with random bytes from random.
        Arrays.fill(b, (byte) 0x00);
        return sKey;
    }

}
