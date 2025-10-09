/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.PQCKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

abstract class PQCKeyPairGenerator extends KeyPairGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private String pqcAlg;

    public PQCKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    public PQCKeyPairGenerator(OpenJCEPlusProvider provider, String algName) {
        this.provider = provider;
        this.pqcAlg = algName;
    }

    /**
     * Initialize based on parameters.
     */
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (params instanceof NamedParameterSpec spec) {
            String name = spec.getName();
            if (pqcAlg.equals("ML-KEM")) {
                if (name.equalsIgnoreCase("ML-KEM-512") || 
                    name.equalsIgnoreCase("ML-KEM-768") ||
                    name.equalsIgnoreCase("ML-KEM-1024")) {
                    pqcAlg = name;
                } else {        
                    throw new InvalidAlgorithmParameterException(
                        "Unsupported parameter set name: " + name);
                }
            } else if (pqcAlg.equals("ML-DSA")) {
                if (name.equalsIgnoreCase("ML-DSA-44") || 
                    name.equalsIgnoreCase("ML-DSA-65") ||
                    name.equalsIgnoreCase("ML-DSA-87")) {
                    pqcAlg = name;
                } else {        
                    throw new InvalidAlgorithmParameterException(
                        "Unsupported parameter set name: " + name);
                }
            } else if (!pqcAlg.equalsIgnoreCase(name)) {
                throw new InvalidAlgorithmParameterException(
                    "Algorithm in AlgorithmParameterSpec: " +spec.getName() + 
                    " must match the Algorithnm for this KeyPairGenerator: " + pqcAlg);
            }
        } else {
            throw new InvalidAlgorithmParameterException(
                    "Unsupported AlgorithmParameterSpec: " + params);
        }
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != -1) {
            throw new InvalidParameterException("keysize not supported");
        }
        // This function is here for compatibility with Oracle and Spi.
        // However, since OCKC does not allow specification of Random,
        // this function does nothing.
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            // Set default if necessary
            switch (pqcAlg) {
                case "ML-KEM":
                    pqcAlg = "ML-KEM-768";
                    break;
                case "ML-DSA":
                    pqcAlg = "ML-DSA-65";
                    break;
                default:
                    //We have the alg already
                    break;
            }

            PQCKey mlkemKey = PQCKey.generateKeyPair(provider.getOCKContext(), pqcAlg, provider);
            byte[] privKeyBytes = mlkemKey.getPrivateKeyBytes();
            PQCPrivateKey privKey = new PQCPrivateKey(provider, PQCKey.createPrivateKey(provider.getOCKContext(),
                                                        pqcAlg, privKeyBytes, provider));
            byte[] pubKeyBytes = mlkemKey.getPublicKeyBytes();
            PQCPublicKey pubKey = new PQCPublicKey(provider, PQCKey.createPublicKey(provider.getOCKContext(),
                                                        pqcAlg, pubKeyBytes, provider));
            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException("Failure in generateKeyPair - " +e.getCause(), e);
        }
    }

    public static final class MLKEM512 extends PQCKeyPairGenerator {

        public MLKEM512(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-512");
        }
    }

    public static final class MLKEM768 extends PQCKeyPairGenerator {

        public MLKEM768(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-768");
        }
    }

    public static final class MLKEM extends PQCKeyPairGenerator {

        public MLKEM(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM");
        }
    }

    public static final class MLKEM1024 extends PQCKeyPairGenerator {

        public MLKEM1024(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-1024");
        }
    }

    public static final class MLDSA44 extends PQCKeyPairGenerator {

        public MLDSA44(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-44");
        }
    }

    public static final class MLDSA extends PQCKeyPairGenerator {

        public MLDSA(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA");
        }
    }

    public static final class MLDSA65 extends PQCKeyPairGenerator {

        public MLDSA65(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-65");
        }
    }

    public static final class MLDSA87 extends PQCKeyPairGenerator {

        public MLDSA87(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-87");
        }
    }

    public static final class SLHDSASHA2128s extends PQCKeyPairGenerator {

        public SLHDSASHA2128s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-128s");
        }
    }

    public static final class SLHDSASHAKE128s extends PQCKeyPairGenerator {

        public SLHDSASHAKE128s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-128s");
        }
    }

    public static final class SLHDSASHA2128f extends PQCKeyPairGenerator {

        public SLHDSASHA2128f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-128f");
        }
    }

    public static final class SLHDSASHAKE128f extends PQCKeyPairGenerator {

        public SLHDSASHAKE128f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-128f");
        }
    }

    public static final class SLHDSASHA2192s extends PQCKeyPairGenerator {

        public SLHDSASHA2192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192s");
        }
    }

    public static final class SLHDSASHAKE192s extends PQCKeyPairGenerator {

        public SLHDSASHAKE192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192s");
        }
    }

    public static final class SLHDSASHA2192f extends PQCKeyPairGenerator {

        public SLHDSASHA2192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192f");
        }
    }

    public static final class SLHDSASHAKE192f extends PQCKeyPairGenerator {

        public SLHDSASHAKE192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192f");
        }
    }

    public static final class SLHDSASHA2256s extends PQCKeyPairGenerator {

        public SLHDSASHA2256s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256s");
        }
    }

    public static final class SLHDSASHAKE256s extends PQCKeyPairGenerator {

        public SLHDSASHAKE256s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-256s");
        }
    }

    public static final class SLHDSASHA2256f extends PQCKeyPairGenerator {

        public SLHDSASHA2256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256f");
        }
    }

    public static final class SLHDSASHAKE256f extends PQCKeyPairGenerator {

        public SLHDSASHAKE256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-256f");
        }
    }
}
