/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

abstract class PBES2Core extends CipherSpi {
    private static final int DEFAULT_SALT_LENGTH = 20;
    private static final int DEFAULT_COUNT = 4096;

    private final AESCipher cipher;
    private final int keyLength; // in bits
    private final int blkSize; // in bits
    private final PBKDF2Core kdf;
    private final String pbeAlgo;
    private final String cipherAlgo;
    private OpenJCEPlusProvider provider = null;
    private int iCount = DEFAULT_COUNT;
    private byte[] salt = null;
    private IvParameterSpec ivSpec = null;

    /**
     * Creates an instance of PBE Scheme 2 according to the selected
     * password-based key derivation function and encryption scheme.
     */
    PBES2Core(String kdfAlgo, String cipherAlgo, int keySize, OpenJCEPlusProvider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        
        blkSize = AESCipher.AES_BLOCK_SIZE;
        this.cipherAlgo = cipherAlgo;
        keyLength = keySize * 8;
        pbeAlgo = "PBEWith" + kdfAlgo + "And" + cipherAlgo + "_" + keyLength;
        this.provider = provider;

        if (cipherAlgo.equalsIgnoreCase("AES")) {
            cipher = new AESCipher(provider);

            switch(kdfAlgo.toLowerCase()) {
                case "hmacsha1":
                    kdf = new PBKDF2Core.HmacSHA1(provider);
                    break;
                case "hmacsha224":
                    kdf = new PBKDF2Core.HmacSHA224(provider);
                    break;
                case "hmacsha256":
                    kdf = new PBKDF2Core.HmacSHA256(provider);
                    break;
                case "hmacsha384":
                    kdf = new PBKDF2Core.HmacSHA384(provider);
                    break;
                case "hmacsha512":
                    kdf = new PBKDF2Core.HmacSHA512(provider);
                    break;
                case "hmacsha512/224":
                    kdf = new PBKDF2Core.HmacSHA512_224(provider);
                    break;
                case "hmacsha512/256":
                    kdf = new PBKDF2Core.HmacSHA512_256(provider);
                    break;
                default:
                    throw new NoSuchAlgorithmException(
                        "No Cipher implementation for " + kdfAlgo);
            }
        } else {
            throw new NoSuchAlgorithmException("No Cipher implementation for " +
                                               pbeAlgo);
        }
        cipher.engineSetMode("CBC");
        cipher.engineSetPadding("PKCS5Padding");
    }

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if ((mode != null) && (!mode.equalsIgnoreCase("CBC"))) {
            throw new NoSuchAlgorithmException("Invalid cipher mode: " + mode);
        }
    }

    protected void engineSetPadding(String paddingScheme)
        throws NoSuchPaddingException {
        if ((paddingScheme != null) &&
            (!paddingScheme.equalsIgnoreCase("PKCS5Padding"))) {
            throw new NoSuchPaddingException("Invalid padding scheme: " +
                                             paddingScheme);
        }
    }

    protected int engineGetBlockSize() {
        return blkSize;
    }

    protected int engineGetOutputSize(int inputLen) {
        return cipher.engineGetOutputSize(inputLen);
    }

    protected byte[] engineGetIV() {
        return cipher.engineGetIV();
    }

    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;
        if (salt == null) {
            // generate random salt and use default iteration count
            salt = new byte[DEFAULT_SALT_LENGTH];
            provider.getSecureRandom(null).nextBytes(salt);
            iCount = DEFAULT_COUNT;
        }
        if (ivSpec == null) {
            // generate random IV
            byte[] ivBytes = new byte[blkSize];
            provider.getSecureRandom(null).nextBytes(ivBytes);
            ivSpec = new IvParameterSpec(ivBytes);
        }
        PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, iCount, ivSpec);
        try {
            params = AlgorithmParameters.getInstance(pbeAlgo, provider);
            params.init(pbeSpec);
        } catch (NoSuchAlgorithmException nsae) {
            // should never happen
            throw new RuntimeException("OpenJCEPlus called, but not configured");
        } catch (InvalidParameterSpecException ipse) {
            // should never happen
            throw new RuntimeException("PBEParameterSpec not supported");
        }
        return params;
    }

    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException ie) {
            throw new InvalidKeyException("requires PBE parameters", ie);
        }
    }

    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Null key");
        }

        byte[] passwdBytes = key.getEncoded();
        char[] passwdChars = null;
        PBEKeySpec pbeSpec;
        try {
            if ((passwdBytes == null) ||
                    !(key.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3))) {
                throw new InvalidKeyException("Missing password");
            }

            // TBD: consolidate the salt, ic and IV parameter checks below

            // Extract salt and iteration count from the key, if present
            if (key instanceof javax.crypto.interfaces.PBEKey) {
                salt = ((javax.crypto.interfaces.PBEKey)key).getSalt();
                if (salt != null && salt.length < 8) {
                    throw new InvalidAlgorithmParameterException(
                            "Salt must be at least 8 bytes long");
                }
                iCount = ((javax.crypto.interfaces.PBEKey)key).getIterationCount();
                if (iCount == 0) {
                    iCount = DEFAULT_COUNT;
                } else if (iCount < 0) {
                    throw new InvalidAlgorithmParameterException(
                            "Iteration count must be a positive number");
                }
            }

            // Extract salt, iteration count and IV from the params, if present
            if (params == null) {
                if (salt == null) {
                    // generate random salt and use default iteration count
                    salt = new byte[DEFAULT_SALT_LENGTH];
                    random.nextBytes(salt);
                    iCount = DEFAULT_COUNT;
                }
                if ((opmode == Cipher.ENCRYPT_MODE) ||
                        (opmode == Cipher.WRAP_MODE)) {
                    // generate random IV
                    byte[] ivBytes = new byte[blkSize];
                    random.nextBytes(ivBytes);
                    ivSpec = new IvParameterSpec(ivBytes);
                }
            } else {
                if (!(params instanceof PBEParameterSpec)) {
                    throw new InvalidAlgorithmParameterException
                            ("Wrong parameter type: PBE expected");
                }
                // salt and iteration count from the params take precedence
                byte[] specSalt = ((PBEParameterSpec) params).getSalt();
                if (specSalt != null && specSalt.length < 8) {
                    throw new InvalidAlgorithmParameterException(
                            "Salt must be at least 8 bytes long");
                }
                salt = specSalt;
                int specICount = ((PBEParameterSpec) params).getIterationCount();
                if (specICount == 0) {
                    specICount = DEFAULT_COUNT;
                } else if (specICount < 0) {
                    throw new InvalidAlgorithmParameterException(
                            "Iteration count must be a positive number");
                }
                iCount = specICount;

                AlgorithmParameterSpec specParams =
                        ((PBEParameterSpec) params).getParameterSpec();
                if (specParams != null) {
                    if (specParams instanceof IvParameterSpec) {
                        ivSpec = (IvParameterSpec)specParams;
                    } else {
                        throw new InvalidAlgorithmParameterException(
                                "Wrong parameter type: IV expected");
                    }
                } else if ((opmode == Cipher.ENCRYPT_MODE) ||
                        (opmode == Cipher.WRAP_MODE)) {
                    // generate random IV
                    byte[] ivBytes = new byte[blkSize];
                    random.nextBytes(ivBytes);
                    ivSpec = new IvParameterSpec(ivBytes);
                } else {
                    throw new InvalidAlgorithmParameterException(
                            "Missing parameter type: IV expected");
                }
            }

            passwdChars = new char[passwdBytes.length];
            for (int i = 0; i < passwdChars.length; i++)
                passwdChars[i] = (char) (passwdBytes[i] & 0x7f);

            pbeSpec = new PBEKeySpec(passwdChars, salt, iCount, keyLength);
            // password char[] was cloned in PBEKeySpec constructor,
            // so we can zero it out here
        } finally {
            if (passwdChars != null) Arrays.fill(passwdChars, '\0');
            if (passwdBytes != null) Arrays.fill(passwdBytes, (byte)0x00);
        }

        PBKDF2KeyImpl s = null;
        byte[] derivedKey;
        try {
            s = (PBKDF2KeyImpl) kdf.engineGenerateSecret(pbeSpec);
            derivedKey = s.getEncoded();
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot construct PBE key", ikse);
        } finally {
            if (s != null) {
                try {
                    s.finalize();
                } catch (Throwable e) {
                   //some error happened
                }
            }
            pbeSpec.clearPassword();
        }

        SecretKeySpec cipherKey = null;
        try {
            cipherKey = new SecretKeySpec(derivedKey, cipherAlgo);
            // initialize the underlying cipher
            cipher.engineInit(opmode, cipherKey, ivSpec, random);
        } finally {
            if (cipherKey != null) {
                byte[] clean = cipherKey.getEncoded();
                Arrays.fill(clean, (byte) 0x00);
            }
            Arrays.fill(derivedKey, (byte) 0x00);
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec pbeSpec = null;
        if (params != null) {
            try {
                pbeSpec = params.getParameterSpec(PBEParameterSpec.class);
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException(
                    "Wrong parameter type: PBE expected");
            }
        }
        engineInit(opmode, key, pbeSpec, random);
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return cipher.engineUpdate(input, inputOffset, inputLen);
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
        throws ShortBufferException {
        return cipher.engineUpdate(input, inputOffset, inputLen,
                             output, outputOffset);
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException {
        return cipher.engineDoFinal(input, inputOffset, inputLen);
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {
        return cipher.engineDoFinal(input, inputOffset, inputLen,
                              output, outputOffset);
    }

    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        return keyLength;
    }

    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException {
        return cipher.engineWrap(key);
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
                               int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException {
        return cipher.engineUnwrap(wrappedKey, wrappedKeyAlgorithm,
                             wrappedKeyType);
    }

    public static final class HmacSHA1AndAES_128 extends PBES2Core {
        public HmacSHA1AndAES_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA1", "AES", 16, provider);
        }
    }

    public static final class HmacSHA224AndAES_128 extends PBES2Core {
        public HmacSHA224AndAES_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA224", "AES", 16, provider);
        }
    }

    public static final class HmacSHA256AndAES_128 extends PBES2Core {
        public HmacSHA256AndAES_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA256", "AES", 16, provider);
        }
    }

    public static final class HmacSHA384AndAES_128 extends PBES2Core {
        public HmacSHA384AndAES_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA384", "AES", 16, provider);
        }
    }

    public static final class HmacSHA512AndAES_128 extends PBES2Core {
        public HmacSHA512AndAES_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA512", "AES", 16, provider);
        }
    }

    public static final class HmacSHA512_224AndAES_128 extends PBES2Core {
        public HmacSHA512_224AndAES_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA512/224", "AES", 16, provider);
        }
    }

    public static final class HmacSHA512_256AndAES_128 extends PBES2Core {
        public HmacSHA512_256AndAES_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA512/256", "AES", 16, provider);
        }
    }

    public static final class HmacSHA1AndAES_256 extends PBES2Core {
        public HmacSHA1AndAES_256(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA1", "AES", 32, provider);
        }
    }

    public static final class HmacSHA224AndAES_256 extends PBES2Core {
        public HmacSHA224AndAES_256(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA224", "AES", 32, provider);
        }
    }

    public static final class HmacSHA256AndAES_256 extends PBES2Core {
        public HmacSHA256AndAES_256(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA256", "AES", 32, provider);
        }
    }

    public static final class HmacSHA384AndAES_256 extends PBES2Core {
        public HmacSHA384AndAES_256(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA384", "AES", 32, provider);
        }
    }

    public static final class HmacSHA512AndAES_256 extends PBES2Core {
        public HmacSHA512AndAES_256(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA512", "AES", 32, provider);
        }
    }

    public static final class HmacSHA512_224AndAES_256 extends PBES2Core {
        public HmacSHA512_224AndAES_256(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA512/224", "AES", 32, provider);
        }
    }
    public static final class HmacSHA512_256AndAES_256 extends PBES2Core {
        public HmacSHA512_256AndAES_256(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("HmacSHA512/256", "AES", 32, provider);
        }
    }
}
