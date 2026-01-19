/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.OCKException;
import com.ibm.crypto.plus.provider.base.OJPKEM;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MLKEMImpl implements KEMSpi {
    OpenJCEPlusProvider provider;
    String alg;
    static int SECRETSIZE  = 32;

    public MLKEMImpl(OpenJCEPlusProvider provider, String alg) {
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

    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. If not null
     * it will be ignored.
     * secureRandom - This parameter is not used and should be null. If not null it
     * will be ignored.
     */
    @Override
    public KEMSpi.EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
            AlgorithmParameterSpec spec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        
        PublicKey pubKey = publicKey;
        if (pubKey == null) {
            throw new InvalidKeyException("Key is null.");
        }

        if (!(pubKey instanceof PQCPublicKey)) {
            // Try and convert this key to a usage PQCPublicKey
            try {
                KeyFactory kf = KeyFactory.getInstance(this.alg, this.provider.getName());
                EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
                pubKey = kf.generatePublic(publicKeySpec);
       
            } catch (Exception e) {
                throw new InvalidKeyException("unsupported key", e);
            }
        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        return new MLKEMEncapsulator(pubKey, spec, null);
    }

    class MLKEMEncapsulator implements KEMSpi.EncapsulatorSpi {

        PublicKey publicKey;
        int size = SECRETSIZE;

        /*
         * spec - The AlgorithmParameterSpec is not used and should be null. 
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
            byte[] secret = new byte[SECRETSIZE];

            if (from < 0 || to > SECRETSIZE || ((to - from) < 0) || (from >= SECRETSIZE)){
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null) {
                throw new NullPointerException();
            }

            try {
                OJPKEM.KEM_encapsulate(provider.getOCKContext(),
                        ((PQCPublicKey) publicKey).getPQCKey().getPKeyId(), encapsulation, secret);
            } catch (OCKException e) {
                throw new ProviderException("OCK Exception: ", e);
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

    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. 
     */
    @Override
    public KEMSpi.DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
            AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
 
        PrivateKey privKey = privateKey;

        if (privKey == null) {
            throw new InvalidKeyException("Key is null.");
        }

        if (!(privKey instanceof PQCPrivateKey)) {
            // Try and convert this key to a usage PQCPrivateKey
            byte[] encoding = null;
            try {
                KeyFactory kf = KeyFactory.getInstance(this.alg, this.provider.getName());
                encoding = privateKey.getEncoded();
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encoding);
                privKey = kf.generatePrivate(privateKeySpec);     
            } catch (Exception e) {
                throw new InvalidKeyException("unsupported key", e);
            } finally {
                Arrays.fill(encoding, (byte) 0);
            }

        }

        if (spec != null) {
            throw new InvalidAlgorithmParameterException("no spec needed");
        }
        return new MLKEMDecapsulator(privKey, null);
    }

    /*
     * spec - The AlgorithmParameterSpec is not used and should be null. 
     */
    class MLKEMDecapsulator implements KEMSpi.DecapsulatorSpi {
        PrivateKey privateKey;
        int size = SECRETSIZE;

        MLKEMDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec) {
            this.privateKey = privateKey;
        }

        @Override
        public SecretKey engineDecapsulate(byte[] cipherText, int from, int to, String algorithm)
                throws DecapsulateException {
            byte[] secret;

            if (from < 0 || to > SECRETSIZE || ((to - from) < 0) || (from >= SECRETSIZE)){
                throw new IndexOutOfBoundsException();
            }
            if (algorithm == null || cipherText == null) {
                throw new NullPointerException();
            }
            try {
                secret = OJPKEM.KEM_decapsulate(provider.getOCKContext(),
                        ((PQCPrivateKey) this.privateKey).getPQCKey().getPKeyId(), cipherText);

            } catch (OCKException e) {
                throw new DecapsulateException("Decapsulation Error: ", e);
            }

            return new SecretKeySpec(secret, from, to - from, algorithm);
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

    public static final class MLKEM512 extends MLKEMImpl {

        public MLKEM512(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-512");
        }
    }

    public static final class MLKEM768 extends MLKEMImpl {

        public MLKEM768(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-768");
        }
    }

    public static final class MLKEM1024 extends MLKEMImpl {

        public MLKEM1024(OpenJCEPlusProvider provider) {           
            super(provider, "ML-KEM-1024");
        }
    }    
}
