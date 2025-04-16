/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.GCMParameterSpec;

public final class GCMParameterGenerator extends AlgorithmParameterGeneratorSpi
        implements AESConstants, GCMConstants {

    private OpenJCEPlusProvider provider = null;
    private AlgorithmParameters generatedParameters;
    // private GCMParameterSpec gcmParamSpec;
    private SecureRandom cryptoRandom = null;

    /**
     * Constructs a new GCMParameterGenerator instance.
     */
    public GCMParameterGenerator(OpenJCEPlusProvider provider) {
        super();
        this.provider = provider;
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        return generatedParameters;
    }

    @Override
    protected void engineInit(int size, SecureRandom random) {
        // we don't care about a size for GCMParameters

        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
        // we'll take the random and use it as an IV
        byte[] iv = new byte[AES_BLOCK_SIZE];

        cryptoRandom.nextBytes(iv);

        GCMParameterSpec ivSpec = new GCMParameterSpec(DEFAULT_TAG_LENGTH, iv);
        // this.gcmParamSpec = ivSpec;
        AlgorithmParameters result;
        try {

            result = AlgorithmParameters.getInstance("AESGCM", provider);

        } catch (NoSuchAlgorithmException e) {
            generatedParameters = null;
            return;
        }
        try {
            result.init(ivSpec);
        } catch (InvalidParameterSpecException e) {
            throw new ProviderException(e.getMessage());
        }

        generatedParameters = result;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException {

        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
        if (algParamSpec instanceof GCMParameterSpec) {
            AlgorithmParameters result;
            try {

                result = AlgorithmParameters.getInstance("AESGCM", provider);

            } catch (NoSuchAlgorithmException e) {
                generatedParameters = null;
                return;
            }
            try {
                // gcmParamSpec = (GCMParameterSpec) algParamSpec;
                result.init(algParamSpec);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException();
            }
            generatedParameters = result;
        }
    }
}
