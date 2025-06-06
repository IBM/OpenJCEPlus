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

abstract class PQCKeyPairGenerator extends KeyPairGeneratorSpi {

    private OpenJCEPlusProvider provider = null;
    private String mlkemAlg;

    public PQCKeyPairGenerator(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    public PQCKeyPairGenerator(OpenJCEPlusProvider provider, String algName) {
        this.provider = provider;
        this.mlkemAlg = algName;
    }

    /**
     * Initialize based on parameters.
     */
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "Params not needed.");
    }
    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != -1) {
            throw new InvalidParameterException("keysize not supported");
        }
        // This functions is here for compatibility with Oracle and Spi
        // However, since OCKC does not allow specification of Random
        // this function does nothing.
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            //System.out.println("Generating KeyPair for " + mlkemAlg);
            PQCKey mlkemKey = PQCKey.generateKeyPair(provider.getOCKContext(), mlkemAlg);
            byte [] privKeyBytes = mlkemKey.getPrivateKeyBytes();
            PQCPrivateKey privKey = new PQCPrivateKey(provider, PQCKey.createPrivateKey(provider.getOCKContext(), 
                                                               mlkemAlg, privKeyBytes));
            byte [] pubKeyBytes = mlkemKey.getPublicKeyBytes();
            PQCPublicKey pubKey = new PQCPublicKey(provider, PQCKey.createPublicKey(provider.getOCKContext(), 
                                                               mlkemAlg, pubKeyBytes));        
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
