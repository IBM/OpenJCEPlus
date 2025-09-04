/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKException;
<<<<<<< HEAD
import com.ibm.crypto.plus.provider.ock.OCKKEM;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
=======
import com.ibm.crypto.plus.provider.ock.OJPKEM;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MLKEMImpl implements KEMSpi {
    OpenJCEPlusProvider provider;
    String alg;

    public MLKEMImpl(OpenJCEPlusProvider provider, String alg) {
<<<<<<< HEAD
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

=======
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
        this.provider = provider;
        this.alg = alg;
    }
    
    private int getEncapsulationLength() {
        int size = 0;

        switch (this.alg) {
            case "ML-KEM-512":
                size = 768;
                break;
            case "ML-KEM-768":
                size = 1088;
                break;
            default:
                size = 1568;
        }
        return size;
    }


<<<<<<< HEAD
    /**
=======
    /*
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
     * secureRandom - This parameter is not used and should be null. If not null it
     * will be ignored.
     */
    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
            AlgorithmParameterSpec spec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
<<<<<<< HEAD
        if (!(publicKey instanceof PQCPublicKey)) {
            throw new InvalidKeyException("unsupported key");
        }

=======
        if (publicKey == null || !(publicKey instanceof PQCPublicKey) ) {
            throw new InvalidKeyException("unsupported key");
        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
        return new MLKEMEncapsulator(publicKey, spec, null);
    }

    class MLKEMEncapsulator implements KEMSpi.EncapsulatorSpi {

        PublicKey publicKey;
        int size = 0;

<<<<<<< HEAD
        /**
         * spec - The AlgorithmParameterSpec is not used and should be null. If not null
         * it will be ignored.
=======
        /*
         * spec - The AlgorithmParameterSpec is not used and should be null. 
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
         * secureRandom - This parameter is not used and should be null. If not null it
         * will be ignored.
         */
        MLKEMEncapsulator(PublicKey publicKey, AlgorithmParameterSpec spec,
                SecureRandom secureRandom) {
            this.publicKey = publicKey;
        }

        @Override
        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            int encapLen = getEncapsulationLength();
            byte[] encapsulation = new byte[encapLen];
            byte[] secret = new byte[32]; //This is always 32 bytes
<<<<<<< HEAD
            try {
                OCKKEM.OCKKEM_encapsulate(provider.getOCKContext(),((PQCPublicKey) publicKey).getOCKKey().getPKeyId(), encapsulation, secret);
            } catch (OCKException e) {
                System.out.println("OCK Exception: " + e.getMessage());
                return null;
=======

            if (from < 0 || to > 31 || ((to - from) < 0) ) {
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null) {
                throw new NullPointerException();
            }

            try {
                OJPKEM.KEM_encapsulate(provider.getOCKContext(),((PQCPublicKey) publicKey).getPQCKey().getPKeyId(), encapsulation, secret);
            } catch (OCKException e) {
                throw new ProviderException("OCK Exception: ", e);
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
            }

            return new KEM.Encapsulated(
                    new SecretKeySpec(secret, from, to - from, algorithm),
                    encapsulation, null);
        }

        @Override
        public int engineEncapsulationSize() {
            return getEncapsulationLength(); 
        }

        @Override
        public int engineSecretSize() {
            return this.size;
        }
    }

<<<<<<< HEAD
    /**
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
=======
    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. 
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
     */
    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
            AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
 
<<<<<<< HEAD
        if (!(privateKey instanceof PQCPrivateKey)) {
            throw new InvalidKeyException("unsupported key");
        }

        return new MLKEMDecapsulator(privateKey, null);
    }

    /**
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
=======
        if (privateKey == null || !(privateKey instanceof PQCPrivateKey)) {
            throw new InvalidKeyException("unsupported key");
        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        return new MLKEMDecapsulator(privateKey, null);
    }

    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. 
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
     */
    class MLKEMDecapsulator implements KEMSpi.DecapsulatorSpi {
        PrivateKey privateKey;
        int size = 0;

        MLKEMDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) {
            this.privateKey = privateKey;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] cipherText, int from, int to, String algorithm)
                throws DecapsulateException {
            byte[] secret;

<<<<<<< HEAD
            try {
                secret = OCKKEM.OCKKEM_decapsulate(provider.getOCKContext(), ((PQCPrivateKey)this.privateKey).getOCKKey().getPKeyId(), cipherText);

            } catch (OCKException e) {
                throw new DecapsulateException(e.getMessage());
=======
            if (from < 0 || to > 31 || ((to - from) < 0) ) {
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null || cipherText == null) {
                throw new NullPointerException();
            }
            try {
                secret = OJPKEM.KEM_decapsulate(provider.getOCKContext(), ((PQCPrivateKey)this.privateKey).getPQCKey().getPKeyId(), cipherText);

            } catch (OCKException e) {
                throw new DecapsulateException("Decapsulation Error: ", e);
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
            }

            return new SecretKeySpec(secret, from, to - from, algorithm);
        }

        @Override
        public int engineEncapsulationSize() {

<<<<<<< HEAD
            return 0; // Needs to be calculated from k of key
=======
            return getEncapsulationLength();
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
        }

        @Override
        public int engineSecretSize() {

            return this.size;
        }

    }
    public static final class MLKEM512 extends MLKEMImpl {

        public MLKEM512(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-512");
<<<<<<< HEAD
=======
            
            if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
                throw new SecurityException("Integrity check failed for: " + provider.getName());
            }

>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
        }
    }

    public static final class MLKEM768 extends MLKEMImpl {

        public MLKEM768(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-768");
<<<<<<< HEAD
=======

            if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
                throw new SecurityException("Integrity check failed for: " + provider.getName());
            }

>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
        }
    }

    public static final class MLKEM1024 extends MLKEMImpl {

<<<<<<< HEAD
        public MLKEM1024(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-1024");
=======
        public MLKEM1024(OpenJCEPlusProvider provider) {           
            super(provider, "ML-KEM-1024");
            
            if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
                throw new SecurityException("Integrity check failed for: " + provider.getName());
            }
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
        }
    }    
}
