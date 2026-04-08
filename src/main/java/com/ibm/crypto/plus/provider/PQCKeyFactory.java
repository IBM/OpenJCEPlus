/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

class PQCKeyFactory extends KeyFactorySpi {

    private OpenJCEPlusProvider provider;
    private String algName = null;

    static Key toPQCKey(OpenJCEPlusProvider provider, Key key) throws InvalidKeyException {
        return (new PQCKeyFactory(provider, key.getAlgorithm())).engineTranslateKey(key);
    }

    private PQCKeyFactory(OpenJCEPlusProvider provider, String name) {
        this.provider = provider;
        this.algName = name;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        byte[] bytes = null;
        try {
            if (keySpec instanceof PKCS8EncodedKeySpec) {
                PrivateKey generated = new PQCPrivateKey(provider,
                        ((PKCS8EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated);
                return generated;
            }

            bytes = getRawBytes(keySpec);
            
            if (!(keySpec instanceof EncodedKeySpec) && checkEncoded(bytes, false)) {
                throw new InvalidKeySpecException("Key spec does not match Spec indicated");
            }

            return new PQCPrivateKey(provider, bytes, algName);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: ", e);
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        byte[] bytes = null;
        try {
            if (keySpec instanceof X509EncodedKeySpec) {
                PQCPublicKey generated = new PQCPublicKey(provider,
                        ((X509EncodedKeySpec) keySpec).getEncoded());
                checkKeyAlgo(generated);
                return generated;
            }

            bytes = getRawBytes(keySpec);

            if (!(keySpec instanceof EncodedKeySpec) && checkEncoded(bytes, true)) {
                throw new InvalidKeySpecException("Key does not match Spec indicated");
            }

            return new PQCPublicKey(provider, bytes, algName);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: ", e);
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        try {
            if (key instanceof com.ibm.crypto.plus.provider.PQCPublicKey) {
                // Determine valid key specs
                Class<?> x509KeySpec = Class.forName("java.security.spec.X509EncodedKeySpec");

                if (x509KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }
            } else if (key instanceof com.ibm.crypto.plus.provider.PQCPrivateKey) {
                // Determine valid key specs
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");

                if (pkcs8KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }

            } else {
                throw new InvalidKeySpecException("Inappropriate key type");
            }
        } catch (ClassNotFoundException | ClassCastException e) {
            throw new InvalidKeySpecException("Unsupported key specification: ", e);
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        // ensure the key algorithm matches the current KeyFactory instance
        checkKeyAlgo(key);

        try {
            if (key instanceof java.security.PublicKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.PQCPublicKey) {
                    return key;
                }
                // Convert key to spec
                X509EncodedKeySpec x509KeySpec = engineGetKeySpec(key,
                        X509EncodedKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePublic(x509KeySpec);
            } else if (key instanceof PrivateKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.PQCPrivateKey) {
                    return key;
                }
                // Convert key to spec
                X509EncodedKeySpec x509KeySpec = engineGetKeySpec(key,
                        X509EncodedKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(x509KeySpec);
            } else {
                throw new InvalidKeyException("Wrong algorithm type");
            }
        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key: ", e);
        }
    }

    /**
     * Extracts the raw byte array from the given {@code KeySpec}.
     *
     * @param keySpec the key specification to extract bytes from; may be {@code null}.
     * @return the raw byte array if the spec is supported and valid; 
     */
    private byte[] getRawBytes(KeySpec keySpec) throws InvalidKeySpecException {
        byte[] bytes = null;
        if (keySpec instanceof ibm.security.internal.spec.RawKeySpec) {
            bytes = ((ibm.security.internal.spec.RawKeySpec) keySpec).getKeyArr();
        } else if (keySpec instanceof sun.security.util.RawKeySpec) {
            bytes = ((sun.security.util.RawKeySpec) keySpec).getKeyArr();
        } else if (keySpec instanceof EncodedKeySpec) {
            EncodedKeySpec eks = (EncodedKeySpec) keySpec;
            if ("RAW".equalsIgnoreCase(eks.getFormat())) {
                bytes = eks.getEncoded();
            }
        }

        if (bytes != null) {
            return bytes;
        }
        throw new InvalidKeySpecException("Inappropriate key specification: " 
            + (keySpec != null ? keySpec.getClass().getName() : "null"));
    }

    // Internal utility method for checking key algorithm
    private void checkKeyAlgo(Key key) throws InvalidKeyException {
        String keyAlg = key.getAlgorithm();
        if (keyAlg == null) {
            throw new InvalidKeyException("Algorithm associate with key is null.");
        } else if (!(key.getAlgorithm().equalsIgnoreCase(this.algName) || 
            (PQCKnownOIDs.findMatch(key.getAlgorithm()).stdName().equalsIgnoreCase(this.algName)))) {
            throw new InvalidKeyException("Expected a " + this.algName + " key, but got " + keyAlg);
        }

    }

    private boolean checkEncoded(byte[] key, boolean pub) {
        try {
            //Check and see if this is an encoded OctetString
            if ( (!pub && key[0] == 0x04) || (pub && key[0] == 0x03)) {
                //This might be encoded
                StringBuilder sb = new StringBuilder();
                for (int i = 2; i < 4; i++) {
                    sb.append(String.format("%02X", key[i]));
                }
                String s = sb.toString();
                int b =  Integer.parseInt(s, 16);
                if (b == (key.length - 4)) {
                    //This is an encoding
                    return true;
                }
            } 
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public static final class MLKEM512 extends PQCKeyFactory {

        public MLKEM512(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-512");
        }
    }

    public static final class MLKEM768 extends PQCKeyFactory {

        public MLKEM768(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-768");
        }
    }

    public static final class MLKEM1024 extends PQCKeyFactory {

        public MLKEM1024(OpenJCEPlusProvider provider) {
            super(provider, "ML-KEM-1024");
        }
    }

    public static final class MLDSA44 extends PQCKeyFactory {

        public MLDSA44(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-44");
        }
    }

    public static final class MLDSA65 extends PQCKeyFactory {

        public MLDSA65(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-65");
        }
    }

    public static final class MLDSA87 extends PQCKeyFactory {

        public MLDSA87(OpenJCEPlusProvider provider) {
            super(provider, "ML-DSA-87");
        }
    }

    public static final class SLHDSASHA2128s extends PQCKeyFactory {

        public SLHDSASHA2128s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-128s");
        }
    }

    public static final class SLHDSASHAKE128s extends PQCKeyFactory {

        public SLHDSASHAKE128s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-128s");
        }
    }

    public static final class SLHDSASHA2128f extends PQCKeyFactory {

        public SLHDSASHA2128f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-128f");
        }
    }

    public static final class SLHDSASHAKE128f extends PQCKeyFactory {

        public SLHDSASHAKE128f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-128f");
        }
    }

    public static final class SLHDSASHA2192s extends PQCKeyFactory {

        public SLHDSASHA2192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192s");
        }
    }

    public static final class SLHDSASHAKE192s extends PQCKeyFactory {

        public SLHDSASHAKE192s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192s");
        }
    }

    public static final class SLHDSASHA2192f extends PQCKeyFactory {

        public SLHDSASHA2192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-192f");
        }
    }

    public static final class SLHDSASHAKE192f extends PQCKeyFactory {

        public SLHDSASHAKE192f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-192f");
        }
    }

    public static final class SLHDSASHA2256s extends PQCKeyFactory {

        public SLHDSASHA2256s(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256s");
        }
    }

    public static final class SLHDSASHAKE256s extends PQCKeyFactory {

        public SLHDSASHAKE256s(OpenJCEPlusProvider provider) {

            super(provider, "SLH-DSA-SHAKE-256s");
        }
    }

    public static final class SLHDSASHA2256f extends PQCKeyFactory {

        public SLHDSASHA2256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHA2-256f");
        }
    }

    public static final class SLHDSASHAKE256f extends PQCKeyFactory {

        public SLHDSASHAKE256f(OpenJCEPlusProvider provider) {
            super(provider, "SLH-DSA-SHAKE-256f");
        }
    }
}
