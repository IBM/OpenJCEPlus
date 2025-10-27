/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.ECKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import sun.security.util.ObjectIdentifier;

public final class ECKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final String EC_LEGACY_DEFAULT_KEYSIZE = "openjceplus.ec.legacy.defaultKeysize";
    private static final boolean legacyECdefault = Boolean.parseBoolean(System.getProperty(EC_LEGACY_DEFAULT_KEYSIZE));

    private OpenJCEPlusProvider provider = null;
    private int keysize = legacyECdefault? 256 : 384;
    private SecureRandom cryptoRandom = null;
    ECParameterSpec ecSpec;
    private ObjectIdentifier oid = null;

    public ECKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) throws InvalidParameterException {
        this.keysize = keysize;
        this.ecSpec = null;
        this.oid = null;
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
        if (provider.isFIPS()) {
            if (keysize < 224 || keysize > 521) {
                throw new InvalidParameterException("Curve not supported in FIPS");
            }
        }

    }

    /**
     * To-Do Currently we cannot generate curves based on parameters.
     */
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof ECParameterSpec)) {
            if (params instanceof ECGenParameterSpec) {
                this.oid = ECNamedCurve.getOIDFromName(((ECGenParameterSpec) params).getName());

                if (this.oid == null)
                    throw new InvalidAlgorithmParameterException(
                            "Curve name not recognized or not supported");
                // this.random = OpenJCEPlus.getSecureRandom(random);
                // this.keysize = ecSpec.getCurve().getField().getFieldSize();
                return;
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Params must be instance of ECParameterSpec or ECGenParameterSpec");
            }
        } else {
            // If the ECParameters map to a known curve
            ECNamedCurve ecNamedCurve = ECParameters.getNamedCurve(((ECParameterSpec) params));
            // ecNamedCurve = null; - Enable this line to test custom curve
            // parameters for now.
            if (ecNamedCurve != null) {
                // System.out.println ("ecnamedCurve = " +
                // ecNamedCurve.getName());
                this.oid = ECNamedCurve.getOIDFromName(ecNamedCurve.getName());
                // this.random = OpenJCEPlus.getSecureRandom(random);
                return;
            }

        }

        if (provider.isFIPS()) {
            if (!ECNamedCurve.isFIPS(this.oid.toString())) {
                throw provider.providerException("Curve not supported in FIPS", null);
            }
        }

        this.ecSpec = (ECParameterSpec) params;
        // this.random = OpenJCEPlus.getSecureRandom(random);
        this.keysize = ecSpec.getCurve().getField().getFieldSize();
    }

    /**
    * 
    */

    @Override
    public KeyPair generateKeyPair() {

        ECKey ecKey = null;
        // set cryptoRandom if initialize() method has been skipped
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(null);
        }

        try {

            if (this.oid != null) {
                ecKey = ECKey.generateKeyPair(provider.getOCKContext(), this.oid.toString(),
                        cryptoRandom);
            } else if (this.ecSpec != null) {

                byte[] encodedCustomCurveParameters = ECParameters.encodeECParameters(this.ecSpec);
                // System.out.println ("generting key pair from a custom
                // specification encodedParameters=" +
                // ECUtils.bytesToHex(encodedCustomCurveParameters));
                ecKey = ECKey.generateKeyPair(provider.getOCKContext(),
                        encodedCustomCurveParameters, cryptoRandom);
            } else if (this.keysize > 0 && (ecSpec == null)) {

                ecKey = ECKey.generateKeyPair(provider.getOCKContext(), this.keysize, cryptoRandom);
            }

            java.security.interfaces.ECPrivateKey privKey = new ECPrivateKey(provider, ecKey);
            java.security.interfaces.ECPublicKey pubKey = new ECPublicKey(provider, ecKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }

    }

    /**
     *
     */
    private void generateParameters() {

    }

}
