/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import com.ibm.crypto.plus.provider.RSAUtil.KeyType;

public class RSAKeyFactory extends KeyFactorySpi {

    public final static int MIN_MODLEN_NONFIPS = 512;
    public final static int MIN_MODLEN_FIPS = 2048;
    public final static int MIN_MODLEN_FIPS_PUB = 1024; //FIPS currently allows signature verification on this size key
    public final static int MAX_MODLEN = 16384;
    public final static List<Integer> ALLOWABLE_MODLEN_FIPS_SIGN = Arrays.asList(2048, 3072, 4096);
    public final static List<Integer> ALLOWABLE_MODLEN_FIPS_VERIFY = Arrays.asList(1024, 2048, 3072, 4096);

    /*
     * If the modulus length is above this value, restrict the size of the
     * exponent to something that can be reasonably computed. We could simply
     * hardcode the exp len to something like 64 bits, but this approach allows
     * flexibility in case impls would like to use larger module and exponent
     * values.
     */
    public final static int MAX_MODLEN_RESTRICT_EXP = 3072;
    public final static int MAX_RESTRICTED_EXPLEN = 64;

    private static final boolean restrictExpLen = Boolean.parseBoolean(
            System.getProperty("com.ibm.crypto.provider.restrictRSAExponent", "false"));

    private OpenJCEPlusProvider provider;
    private KeyType type = KeyType.RSA;

    static RSAKey toRSAKey(OpenJCEPlusProvider provider, Key key) throws InvalidKeyException {
        // FIXME
        // PKCS11 returns keys that extend RSAPrivateKey _AND_ RSAPrivateCrtKey
        // but the CRT private key information is not available. If we get such
        // a condition, then use a RSAPrivateKey class instead.
        //
        // if( key instanceof RSAPrivateCrtKey ) {
        // java.security.interfaces.RSAPrivateCrtKey priv =
        // (java.security.interfaces.RSAPrivateCrtKey)key;
        //
        // if( priv.getCrtCoefficient() == null ) {
        // return new RSAPrivateKey( priv.getModulus(), priv.getPublicExponent()
        // );
        // }
        // }
        KeyType type = KeyType.lookup(key.getAlgorithm());

        return (RSAKey) new RSAKeyFactory(provider, type).engineTranslateKey(key);
    }

    /**
     * Check the length of an RSA key modulus/exponent to make sure it is not
     * too short or long. Some impls have their own min and max key sizes that
     * may or may not match with a system defined value.
     *
     * @param modulusLen
     *            the bit length of the RSA modulus.
     * @param exponent
     *            the RSA exponent
     * @param minModulusLen
     *            if > 0, check to see if modulusLen is at least this long,
     *            otherwise unused.
     * @param maxModulusLen
     *            caller will allow this max number of bits. Allow the smaller
     *            of the system-defined maximum and this param.
     *
     * @throws InvalidKeyException
     *             if any of the values are unacceptable.
     */
    static void checkKeyLengths(int modulusLen, BigInteger exponent, int minModulusLen,
            int maxModulusLen) throws InvalidKeyException {

        if ((minModulusLen > 0) && (modulusLen < (minModulusLen))) {
            throw new InvalidKeyException(
                    "RSA keys must be at least " + minModulusLen + " bits long");
        }

        // Even though our policy file may allow this, we don't want
        // either value (mod/exp) to be too big.

        int maxLen = Math.min(maxModulusLen, MAX_MODLEN);

        // If a RSAPrivateKey/RSAPublicKey, make sure the
        // modulus len isn't too big.
        if (modulusLen > maxLen) {
            throw new InvalidKeyException("RSA keys must be no longer than " + maxLen + " bits");
        }

        // If a RSAPublicKey, make sure the exponent isn't too big.
        if (restrictExpLen && (exponent != null) && (modulusLen > MAX_MODLEN_RESTRICT_EXP)
                && (exponent.bitLength() > MAX_RESTRICTED_EXPLEN)) {
            throw new InvalidKeyException(
                    "RSA exponents can be no longer than " + MAX_RESTRICTED_EXPLEN + " bits "
                            + " if modulus is greater than " + MAX_MODLEN_RESTRICT_EXP + " bits");
        }
    }

    /**
     * Check the length of an RSA key modulus/exponent to make sure it is not
     * too short or long. Some impls have their own min and max key sizes that
     * may or may not match with a system defined value.
     *
     * @param modulusLen
     *            the bit length of the RSA modulus.
     * @param exponent
     *            the RSA exponent
     * @param minModulusLen
     *            if > 0, check to see if modulusLen is at least this long,
     *            otherwise unused.
     * @param maxModulusLen
     *            caller will allow this max number of bits. Allow the smaller
     *            of the system-defined maximum and this param.
     * @param specificModulesLen
     *            specific module length for sign/verify.
     *
     * @throws InvalidKeyException
     *             if any of the values are unacceptable.
     */
    static void checkKeyLengths(int modulusLen, BigInteger exponent, int minModulusLen,
            int maxModulusLen, List<Integer> specificModulesLen, String flag) throws InvalidKeyException {

        checkKeyLengths(modulusLen, exponent, minModulusLen, maxModulusLen);
        if ((specificModulesLen != null) && (!specificModulesLen.contains(modulusLen))) {
            if (flag.equals("verify")) {
                throw new InvalidKeyException("In FIPS mode, only 1024, 2048, 3072, or 4096 size of RSA key is accepted.");
            } else if (flag.equals("sign")){
                throw new InvalidKeyException("In FIPS mode, only 2048, 3072, or 4096 size of RSA key is accepted.");
            }
        }
    }

    /**
     * For compatibility, we round up to the nearest byte here: some Key impls
     * might pass in a value within a byte of the real value.
     */
    static void checkRSAProviderKeyLengths(OpenJCEPlusProvider provider, int modulusLen,
            BigInteger exponent) throws InvalidKeyException {
        if (provider.isFIPS()) {
            if (exponent != null) {
                checkKeyLengths(((modulusLen + 7) & ~7), exponent,
                        RSAKeyFactory.MIN_MODLEN_FIPS_PUB, Integer.MAX_VALUE);
            } else {
                checkKeyLengths(((modulusLen + 7) & ~7), exponent, RSAKeyFactory.MIN_MODLEN_FIPS,
                        Integer.MAX_VALUE);
            }
        } else {
            checkKeyLengths(((modulusLen + 7) & ~7), exponent, RSAKeyFactory.MIN_MODLEN_NONFIPS,
                    Integer.MAX_VALUE);
        }
    }

    public RSAKeyFactory(OpenJCEPlusProvider provider) {
        this.provider = provider;
        this.type = KeyType.RSA;
    }

    private RSAKeyFactory(OpenJCEPlusProvider provider, KeyType type) {
        this.provider = provider;
        this.type = type;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                java.security.interfaces.RSAPrivateKey generated = RSAPrivateCrtKey.newKey(provider,
                        ((PKCS8EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated, type.keyAlgo());
                return generated;

            } else if (keySpec instanceof RSAPrivateCrtKeySpec) {

                RSAPrivateCrtKeySpec rSpec = (RSAPrivateCrtKeySpec) keySpec;
                try {
                    return new RSAPrivateCrtKey(
                            RSAUtil.createAlgorithmId(this.type, rSpec.getParams()), provider,
                            rSpec.getModulus(), rSpec.getPublicExponent(),
                            rSpec.getPrivateExponent(), rSpec.getPrimeP(), rSpec.getPrimeQ(),
                            rSpec.getPrimeExponentP(), rSpec.getPrimeExponentQ(),
                            rSpec.getCrtCoefficient());
                } catch (ProviderException e) {
                    throw new InvalidKeySpecException(e);
                }
            } else if (keySpec instanceof RSAPrivateKeySpec) {
                RSAPrivateKeySpec rSpec = (RSAPrivateKeySpec) keySpec;
                try {
                    return new RSAPrivateKey(
                            RSAUtil.createAlgorithmId(this.type, rSpec.getParams()), provider,
                            rSpec.getModulus(), rSpec.getPrivateExponent());
                } catch (ProviderException e) {
                    throw new InvalidKeySpecException(e);
                }
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof RSAPublicKeySpec) {
                RSAPublicKeySpec rsaPubKeySpec = (RSAPublicKeySpec) keySpec;
                try {
                    return new RSAPublicKey(
                            RSAUtil.createAlgorithmId(this.type, rsaPubKeySpec.getParams()),
                            provider, rsaPubKeySpec.getModulus(),
                            rsaPubKeySpec.getPublicExponent());
                } catch (ProviderException e) {
                    throw new InvalidKeySpecException(e);
                }
            } else if (keySpec instanceof X509EncodedKeySpec) {
                java.security.interfaces.RSAPublicKey generated = new RSAPublicKey(provider,
                        ((X509EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated, type.keyAlgo());
                return generated;
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        try {
            if (key instanceof java.security.interfaces.RSAPublicKey) {
                // Determine valid key specs
                Class<?> rsaPubKeySpec = Class.forName("java.security.spec.RSAPublicKeySpec");
                Class<?> x509KeySpec = Class.forName("java.security.spec.X509EncodedKeySpec");
                if (keySpec.isAssignableFrom(rsaPubKeySpec)) {
                    java.security.interfaces.RSAPublicKey rsaPubKey = (java.security.interfaces.RSAPublicKey) key;
                    return keySpec.cast(new RSAPublicKeySpec(rsaPubKey.getModulus(),
                            rsaPubKey.getPublicExponent(), rsaPubKey.getParams()));
                } else if (keySpec.isAssignableFrom(x509KeySpec)) {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }
            } else if (key instanceof java.security.interfaces.RSAPrivateCrtKey) {
                // Determine valid key specs
                Class<?> rsaPrivKeySpec = Class.forName("java.security.spec.RSAPrivateKeySpec");
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");
                if (keySpec.isAssignableFrom(RSAPrivateCrtKeySpec.class)) {
                    java.security.interfaces.RSAPrivateCrtKey rsaPrivCrtKey = (java.security.interfaces.RSAPrivateCrtKey) key;
                    return keySpec.cast(new RSAPrivateCrtKeySpec(rsaPrivCrtKey.getModulus(),
                            rsaPrivCrtKey.getPublicExponent(), rsaPrivCrtKey.getPrivateExponent(),
                            rsaPrivCrtKey.getPrimeP(), rsaPrivCrtKey.getPrimeQ(),
                            rsaPrivCrtKey.getPrimeExponentP(), rsaPrivCrtKey.getPrimeExponentQ(),
                            rsaPrivCrtKey.getCrtCoefficient(), rsaPrivCrtKey.getParams()));

                } else if (keySpec.isAssignableFrom(pkcs8KeySpec)) {
                    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
                } else if (keySpec.isAssignableFrom(rsaPrivKeySpec)) {
                    java.security.interfaces.RSAPrivateKey rsaPrivKey = (java.security.interfaces.RSAPrivateKey) key;
                    return keySpec.cast(new RSAPrivateKeySpec(rsaPrivKey.getModulus(),
                            rsaPrivKey.getPrivateExponent(), rsaPrivKey.getParams()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }
            } else if (key instanceof java.security.interfaces.RSAPrivateKey) {
                // Determine valid key specs
                Class<?> rsaPrivKeySpec = Class.forName("java.security.spec.RSAPrivateKeySpec");
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");
                if (keySpec.isAssignableFrom(rsaPrivKeySpec)) {
                    java.security.interfaces.RSAPrivateKey rsaPrivKey = (java.security.interfaces.RSAPrivateKey) key;
                    return keySpec.cast(new RSAPrivateKeySpec(rsaPrivKey.getModulus(),
                            rsaPrivKey.getPrivateExponent(), rsaPrivKey.getParams()));
                } else if (keySpec.isAssignableFrom(pkcs8KeySpec)) {
                    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }
            } else {
                throw new InvalidKeySpecException("Inappropriate key type");
            }
        } catch (ClassNotFoundException | ClassCastException e) {
            throw new InvalidKeySpecException("Unsupported key specification: " + e.getMessage());
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        // ensure the key algorithm matches the current KeyFactory instance
        checkKeyAlgo(key, type.keyAlgo());

        try {
            if (key instanceof java.security.interfaces.RSAPublicKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.RSAPublicKey) {
                    return key;
                }
                // Convert key to spec
                RSAPublicKeySpec rsaPubKeySpec = engineGetKeySpec(key,
                        RSAPublicKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePublic(rsaPubKeySpec);
            } else if (key instanceof java.security.interfaces.RSAPrivateCrtKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.RSAPrivateCrtKey) {
                    return key;
                }
                // Convert key to spec
                RSAPrivateKeySpec rsaPrivKeySpec = (RSAPrivateKeySpec) engineGetKeySpec(key,
                        RSAPrivateCrtKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(rsaPrivKeySpec);
            } else if (key instanceof java.security.interfaces.RSAPrivateKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.RSAPrivateKey) {
                    return key;
                }
                // Convert key to spec
                RSAPrivateKeySpec rsaPrivKeySpec = engineGetKeySpec(key,
                        RSAPrivateKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(rsaPrivKeySpec);
            } else {
                throw new InvalidKeyException("Wrong algorithm type");
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key: " + e.getMessage());
        }
    }

    // Internal utility method for checking key algorithm
    private static void checkKeyAlgo(Key key, String expectedAlg) throws InvalidKeyException {
        String keyAlg = key.getAlgorithm();
        if (keyAlg == null) {
            //Thread.dumpStack();
            throw new InvalidKeyException("Expected a " + expectedAlg + " key, but got " + keyAlg);
        } else if (RSAUtil.isRSAPSS(key.getAlgorithm())) {
            if (RSAUtil.isRSAPSS(expectedAlg) || expectedAlg.equalsIgnoreCase("RSA")) {
                return;
            }
        } else if (key.getAlgorithm().equalsIgnoreCase("RSA") && RSAUtil.isRSAPSS(expectedAlg)) {
            return;
        } else if (!key.getAlgorithm().equalsIgnoreCase(expectedAlg)) {
            throw new InvalidKeyException("Expected a " + expectedAlg + " key, but got " + keyAlg);
        }


    }

    public static final class Legacy extends RSAKeyFactory {
        public Legacy(OpenJCEPlusProvider provider) {
            super(provider, KeyType.RSA);
        }
    }

    public static final class PSS extends RSAKeyFactory {
        public PSS(OpenJCEPlusProvider provider) {
            super(provider, KeyType.PSS);
        }
    }
}
