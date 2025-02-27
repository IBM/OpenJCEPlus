/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.RSAUtil.KeyType;
import com.ibm.crypto.plus.provider.ock.RSAKey;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import sun.security.x509.AlgorithmId;

abstract class RSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private int keysize = 2048;
    private BigInteger publicExponent = RSAKeyGenParameterSpec.F4;
    static int DEF_RSA_KEY_SIZE = 2048;
    static int DEF_RSASSA_PSS_KEY_SIZE = 2048;
    private KeyType type = RSAUtil.KeyType.RSA;
    private AlgorithmId rsaId;

    RSAKeyPairGenerator(OpenJCEPlusProvider provider, KeyType type, int keySize) {
        this.provider = provider;
        this.type = type;
        this.rsaId = RSAUtil.createAlgorithmId(type, null);
        this.keysize = keySize;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize <= 0) {
            throw new InvalidParameterException("keysize size cannot be <= 0");
        }

        if ((keysize % 8) != 0) {
            throw new InvalidParameterException("Modulus size must be multiple of 8");
        }

        // do not allow unreasonably small or large key sizes,
        // probably user error
        try {
            if (provider.isFIPS()) {
                RSAKeyFactory.checkKeyLengths(keysize, RSAKeyGenParameterSpec.F4,
                        RSAKeyFactory.MIN_MODLEN_FIPS, 64 * 1024);
            } else {
                RSAKeyFactory.checkKeyLengths(keysize, RSAKeyGenParameterSpec.F4,
                        RSAKeyFactory.MIN_MODLEN_NONFIPS, 64 * 1024);
            }
        } catch (InvalidKeyException e) {
            throw new InvalidParameterException(e.getMessage());
        }

        this.keysize = keysize;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {

        if (params instanceof RSAKeyGenParameterSpec == false) {
            throw new InvalidAlgorithmParameterException(
                    "Params must be instance of RSAKeyGenParameterSpec");
        }
        RSAKeyGenParameterSpec rsaSpec = (RSAKeyGenParameterSpec) params;

        this.keysize = rsaSpec.getKeysize();

        if (this.keysize <= 0) {
            throw new InvalidParameterException("keysize size cannot be <= 0");
        }

        this.publicExponent = rsaSpec.getPublicExponent();

        if ((this.keysize % 8) != 0) {
            throw new InvalidAlgorithmParameterException("Modulus size must be multiple of 8");
        }

        // do not allow unreasonably large key sizes, probably user error
        try {
            if (provider.isFIPS()) {
                RSAKeyFactory.checkKeyLengths(this.keysize, publicExponent,
                        RSAKeyFactory.MIN_MODLEN_FIPS, 64 * 1024);
            } else {
                RSAKeyFactory.checkKeyLengths(this.keysize, publicExponent,
                        RSAKeyFactory.MIN_MODLEN_NONFIPS, 64 * 1024);
            }
        } catch (InvalidKeyException e) {
            throw new InvalidAlgorithmParameterException("Invalid key sizes", e);
        }

        if (this.publicExponent == null) {
            this.publicExponent = RSAKeyGenParameterSpec.F4;
        } else {
            if (this.publicExponent.compareTo(RSAKeyGenParameterSpec.F0) < 0) {
                throw new InvalidAlgorithmParameterException("Public exponent must be 3 or larger");
            }
            if (this.publicExponent.bitLength() > this.keysize) {
                throw new InvalidAlgorithmParameterException(
                        "Public exponent must be smaller than key size");
            }
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            RSAKey rsaKey = RSAKey.generateKeyPair(provider.getOCKContext(), this.keysize,
                    this.publicExponent);
            java.security.interfaces.RSAPrivateKey privKey = new RSAPrivateCrtKey(rsaId, provider, rsaKey);
            java.security.interfaces.RSAPublicKey pubKey = new RSAPublicKey(rsaId, provider, rsaKey);
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair", e);
        }
    }

    public static final class Legacy extends RSAKeyPairGenerator {
        public Legacy(OpenJCEPlusProvider provider) {
            super(provider, KeyType.RSA, DEF_RSA_KEY_SIZE);
        }
    }

    public static final class PSS extends RSAKeyPairGenerator {
        public PSS(OpenJCEPlusProvider provider) {
            super(provider, KeyType.PSS, DEF_RSASSA_PSS_KEY_SIZE);
        }
    }

}
