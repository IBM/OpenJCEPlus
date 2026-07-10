/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This is an implementation of the PBMAC1 algorithms as defined
 * in PKCS#5 v2.1 standard.
 */
abstract class PBMAC1Core extends HmacCore {

    private final String kdfAlgo;
    private final int blockLength;
    private final OpenJCEPlusProvider provider;
    
    PBMAC1Core(String kdfAlgo, String hashAlgo, int blockLength, OpenJCEPlusProvider provider) {
        super(provider, hashAlgo, blockLength);
        this.kdfAlgo = kdfAlgo;
        this.blockLength = blockLength;
        this.provider = provider;
    }

    private PBKDF2Core getKDFImpl(String algo) {
        PBKDF2Core kdf;
        switch (algo) {
            case "HmacSHA1":
                kdf = new PBKDF2Core.HmacSHA1(provider);
                break;
            case "HmacSHA224":
                kdf = new PBKDF2Core.HmacSHA224(provider);
                break;
            case "HmacSHA256":
                kdf = new PBKDF2Core.HmacSHA256(provider);
                break;
            case "HmacSHA384":
                kdf = new PBKDF2Core.HmacSHA384(provider);
                break;
            case "HmacSHA512":
                kdf = new PBKDF2Core.HmacSHA512(provider);
                break;
            default:
                throw new ProviderException("No MAC implementation for " + algo);
        }

        return kdf;
    }

    protected void engineInit(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        char[] password;
        byte[] keySalt = null;
        int keyIterationCount = 0;

        if (key instanceof javax.crypto.interfaces.PBEKey pbeKey) {
            password = pbeKey.getPassword();
            keySalt = pbeKey.getSalt();
            keyIterationCount = pbeKey.getIterationCount();
        } else if (key instanceof SecretKey) {
            byte[] passwordBytes;
            if (!(key.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3)) ||
                    (passwordBytes = key.getEncoded()) == null) {
                throw new InvalidKeyException("Missing password");
            }

            password = new char[passwordBytes.length];
            for (int i = 0; i < password.length; i++) {
                password[i] = (char) (passwordBytes[i] & 0x7f);
            }

            Arrays.fill(passwordBytes, (byte) 0x00);
        } else {
            throw new InvalidKeyException("SecretKey of PBE type required");
        }

        PBEKeySpec pbeSpec;
        try {
            if (params == null) {
                if ((keySalt == null) || (keyIterationCount == 0)) {
                    throw new InvalidAlgorithmParameterException("PBEParameterSpec required for salt and iteration count");
                }
            } else if (!(params instanceof PBEParameterSpec)) {
                throw new InvalidAlgorithmParameterException("PBEParameterSpec type required");
            } else {
                PBEParameterSpec pbeParams = (PBEParameterSpec) params;

                if (keySalt != null && (!Arrays.equals(pbeParams.getSalt(), keySalt))) {
                    throw new InvalidAlgorithmParameterException("Inconsistent value of salt between key and params");
                }
                keySalt = pbeParams.getSalt();

                if (keyIterationCount != 0 && (keyIterationCount != pbeParams.getIterationCount())) {
                    throw new InvalidAlgorithmParameterException("Different iteration count between key and params");
                }
                keyIterationCount = pbeParams.getIterationCount();
            }

            if (keySalt.length < 8) {
                throw new InvalidAlgorithmParameterException("Salt must be at least 8 bytes long");
            }
            if (keyIterationCount <= 0) {
                throw new InvalidAlgorithmParameterException("IterationCount must be a positive number");
            }

            pbeSpec = new PBEKeySpec(password, keySalt, keyIterationCount, blockLength);
        } finally {
            Arrays.fill(password, '\0');
        }

        PBKDF2KeyImpl s = null;
        byte[] derivedKey = null;
        SecretKeySpec cipherKey = null;
        try {
            PBKDF2Core kdf = getKDFImpl(kdfAlgo);
            s = (PBKDF2KeyImpl) kdf.engineGenerateSecret(pbeSpec);
            derivedKey = s.getEncoded();
            cipherKey = new SecretKeySpec(derivedKey, kdfAlgo);
            super.engineInit(cipherKey, null);
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot construct PBE key", ikse);
        } finally {
            if (derivedKey != null) {
                Arrays.fill(derivedKey, (byte) 0x00);
            }
            pbeSpec.clearPassword();
        }
    }

    public static final class HmacSHA1 extends PBMAC1Core {
        public HmacSHA1(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA1", "SHA1", 64, provider);
        }
    }

    public static final class HmacSHA224 extends PBMAC1Core {
        public HmacSHA224(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA224", "SHA224", 64, provider);
        }
    }

    public static final class HmacSHA256 extends PBMAC1Core {
        public HmacSHA256(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA256", "SHA256", 64, provider);
        }
    }

    public static final class HmacSHA384 extends PBMAC1Core {
        public HmacSHA384(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA384", "SHA384", 128, provider);
        }
    }

    public static final class HmacSHA512 extends PBMAC1Core {
        public HmacSHA512(OpenJCEPlusProvider provider) throws NoSuchAlgorithmException {
            super("HmacSHA512", "SHA512", 128, provider);
        }
    }
}
