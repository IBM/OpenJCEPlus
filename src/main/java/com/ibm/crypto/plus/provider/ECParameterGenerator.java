/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.ECKey;
import java.security.AlgorithmParameterGeneratorSpi;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

public final class ECParameterGenerator extends AlgorithmParameterGeneratorSpi {
    private OpenJCEPlusProvider provider = null;
    private int keysize = 0;
    private AlgorithmParameterSpec algParamSpec = null;

    public ECParameterGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    @Override
    protected void engineInit(int size, SecureRandom random) {
        switch (size) {
            case 192:
            case 224:
            case 256:
            case 384:
            case 521:
                this.keysize = size;
                break;
            default:
                throw new InvalidParameterException("Valid key sizes are: 192, 224, 256, 384, 521");

        }

    }

    @Override
    protected void engineInit(AlgorithmParameterSpec genParamSpec, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        this.algParamSpec = genParamSpec;

    }

    @Override
    protected AlgorithmParameters engineGenerateParameters() {
        AlgorithmParameters algParams = null;
        try {

            if (keysize > 0) {
                algParams = AlgorithmParameters.getInstance("EC", provider);
                byte[] encodedParams = ECKey.generateParameters(provider.getOCKContext(),
                        this.keysize);
                algParams.init(encodedParams);
                return algParams;
            } else if (algParamSpec != null) {
                if (algParamSpec instanceof ECGenParameterSpec) {
                    algParams = AlgorithmParameters.getInstance("EC", provider);
                    String curveName = ((ECGenParameterSpec) algParamSpec).getName();
                    byte[] encodedParams = ECKey.generateParameters(provider.getOCKContext(),
                            curveName);
                    algParams.init(encodedParams);
                    return algParams;
                }
                throw new ProviderException("ECParameterSpec not supported");
            }

        } catch (Exception e) {
            throw provider.providerException("Failure in generateGenerateParameters", e);
        }
        return algParams;
    }

}
