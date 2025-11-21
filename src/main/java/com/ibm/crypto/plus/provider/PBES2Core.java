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
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import sun.security.util.PBEUtil;

abstract class PBES2Core extends CipherSpi {
    private final AESCipher cipher;
    private final int keyLength; // in bits
    private final int blkSize; // in bits
    private final PBKDF2Core kdf;
    private final String pbeAlgo;
    private final String cipherAlgo;
    private final PBEUtil.PBES2Params pbes2Params = new PBEUtil.PBES2Params();
    private OpenJCEPlusProvider provider = null;

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
        return pbes2Params.getAlgorithmParameters(
                blkSize, pbeAlgo, provider, provider.getSecureRandom(null));
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
        PBEKeySpec pbeSpec = pbes2Params.getPBEKeySpec(blkSize, keyLength,
                opmode, key, params, random);
        PBKDF2KeyImpl s = null;
        byte[] derivedKey;
        try {
            s = (PBKDF2KeyImpl) kdf.engineGenerateSecret(pbeSpec);
            derivedKey = s.getEncoded();
        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot construct PBE key", ikse);
        } finally {
            pbeSpec.clearPassword();
        }

        SecretKeySpec cipherKey = null;
        try {
            cipherKey = new SecretKeySpec(derivedKey, cipherAlgo);
            // initialize the underlying cipher
            cipher.engineInit(opmode, cipherKey, pbes2Params.getIvSpec(), random);
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
        engineInit(opmode, key, PBEUtil.PBES2Params.getParameterSpec(params),
                random);
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
