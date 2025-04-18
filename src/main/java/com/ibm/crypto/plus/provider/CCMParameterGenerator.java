/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import ibm.security.internal.spec.CCMParameterSpec;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public final class CCMParameterGenerator extends AlgorithmParameterGeneratorSpi
        implements AESConstants, CCMConstants {

    private OpenJCEPlusProvider provider = null;
    private AlgorithmParameters generatedParameters;
    private SecureRandom cryptoRandom = null;

    /**
     * Constructs a new CCMParameterGenerator instance.
     */
    public CCMParameterGenerator(OpenJCEPlusProvider provider) {
        super();
        this.provider = provider;
    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        return generatedParameters;
    }

    @Override
    protected void engineInit(int tagLen, SecureRandom random) {
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }

        byte[] iv = new byte[DEFAULT_AES_CCM_IV_LENGTH];
        cryptoRandom.nextBytes(iv);
        CCMParameterSpec ccmParameterSpec = new CCMParameterSpec(tagLen, iv); // tagLen is the tag length specified in bits

        AlgorithmParameters result;
        try {
            result = AlgorithmParameters.getInstance("CCM", provider);
        } catch (NoSuchAlgorithmException e) {
            generatedParameters = null;
            return;
        }

        try {
            result.init(ccmParameterSpec);
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

        if (algParamSpec instanceof CCMParameterSpec) {
            AlgorithmParameters result;
            try {
                result = AlgorithmParameters.getInstance("CCM", provider);

            } catch (NoSuchAlgorithmException e) {
                generatedParameters = null;
                return;
            }
            try {
                result.init(algParamSpec);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException();
            }
            generatedParameters = result;
        } else {
            InvalidAlgorithmParameterException iape = new InvalidAlgorithmParameterException(
                    "An invalid AlgorithmParameterSpec object was received.");
            throw iape;
        }
    }
}
