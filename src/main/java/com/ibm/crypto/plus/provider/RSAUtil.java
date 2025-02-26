/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

/**
 * Utility class for SunRsaSign provider.
 * Currently used by RSAKeyPairGenerator and RSAKeyFactory.
 */
final class RSAUtil {

    public enum KeyType {
        RSA("RSA"), PSS(RSAUtil.RSAPSS_NAME),;

        private final String algo;

        KeyType(String keyAlgo) {
            this.algo = keyAlgo;
        }

        public String keyAlgo() {
            return algo;
        }

        private String[] keyAliases() {
            return RSAUtil.RSAPSS_ALIASES;
        }

        public static KeyType lookup(String name) throws InvalidKeyException, ProviderException {
            if (name == null) {
                throw new InvalidKeyException("Null key algorithm");
            }
            if (name.equalsIgnoreCase("RSA")) {
                return KeyType.RSA;
            } else if (RSAUtil.isRSAPSS(name)) {
                return KeyType.PSS;
            }
            // no match
            throw new ProviderException("Unsupported algorithm " + name);
        }
    }

    public static void checkParamsAgainstType(KeyType type, AlgorithmParameterSpec paramSpec)
            throws ProviderException {
        switch (type) {
            case RSA:
                if (paramSpec != null) {
                    throw new ProviderException("null params expected for " + type.keyAlgo());
                }
                break;
            case PSS:
                if ((paramSpec != null) && !(paramSpec instanceof PSSParameterSpec)) {
                    throw new ProviderException("PSSParmeterSpec expected for " + type.keyAlgo());
                }
                break;
            default:
                throw new ProviderException("Unsupported RSA algorithm " + type);
        }
    }

    public static AlgorithmId createAlgorithmId(KeyType type, AlgorithmParameterSpec paramSpec)
            throws ProviderException {

        checkParamsAgainstType(type, paramSpec);

        ObjectIdentifier oid = null;
        AlgorithmParameters params = null;
        try {
            switch (type) {
                case RSA:
                    oid = AlgorithmId.RSAEncryption_oid;
                    break;
                case PSS:
                    if (paramSpec != null) {
                        params = AlgorithmParameters.getInstance(type.keyAlgo());
                        params.init(paramSpec);
                    }
                    oid = AlgorithmId.RSASSA_PSS_oid;
                    break;
                default:
                    throw new ProviderException("Unsupported RSA algorithm " + type);
            }
            AlgorithmId result;
            if (params == null) {
                result = new AlgorithmId(oid);
            } else {
                result = new AlgorithmId(oid, params);
            }
            return result;
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            // should not happen
            throw new ProviderException(e);
        }
    }

    public static AlgorithmParameterSpec getParamSpec(AlgorithmId algid) throws ProviderException {
        if (algid == null) {
            throw new ProviderException("AlgorithmId should not be null");
        }
        return getParamSpec(algid.getParameters());
    }

    public static AlgorithmParameterSpec getParamSpec(AlgorithmParameters params)
            throws ProviderException {
        if (params == null)
            return null;

        try {
            String algName = params.getAlgorithm();
            KeyType type = KeyType.lookup(algName);
            Class<? extends AlgorithmParameterSpec> specCls;
            switch (type) {
                case RSA:
                    throw new ProviderException("No params accepted for " + type.keyAlgo());
                case PSS:
                    specCls = PSSParameterSpec.class;
                    break;
                default:
                    throw new ProviderException("Unsupported RSA algorithm: " + algName);
            }
            return params.getParameterSpec(specCls);
        } catch (ProviderException pe) {
            // pass it up
            throw pe;
        } catch (Exception e) {
            throw new ProviderException(e);
        }
    }

    public static final String RSAPSS_NAME = "RSASSA-PSS";

    /*
     *  Valid aliases:
     *  RSASSA-PSS
     *  RSAPSS
     *  RSA-PSS
     *  RSASA-PSS
     *  1.2.840.113549.1.1.10
     *  OID.1.2.840.113549.1.1.10
     */
    public static final String[] RSAPSS_ALIASES = {"RSASSA-PSS", "RSAPSS", "RSA-PSS", "RSASA-PSS",
            "1.2.840.113549.1.1.10", "OID.1.2.840.113549.1.1.10"};

    public static boolean isRSAPSS(String name) {
        if (name == null || name.length() <= 0) {
            return false;
        }
        for (String s : RSAPSS_ALIASES) {
            if (name.equalsIgnoreCase(s)) {
                return true;
            }
        }
        return false;
    }
}
