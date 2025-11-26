/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.Padding;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

abstract class PBES1Core extends CipherSpi {
    private final String pbeAlgo;
    private final String cipheralgo;
    private final int keysize;
    private final LegacyCipher cipher;
    private byte[] salt;
    private int iterationCount;
    private OpenJCEPlusProvider provider = null;

    private static final int DEFAULT_ITERATION_COUNT = 1024;
    private static final int DEFAULT_SALT_LENGTH = 20;
    private static final int CIPHER_KEY = 1;
    private static final int CIPHER_IV = 2;

    PBES1Core(String cipheralgo, String mode, Padding padding, int keysize, OpenJCEPlusProvider provider)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.provider = provider;
        this.cipheralgo = cipheralgo;
        this.pbeAlgo = cipheralgo.equals("DESede") ? "PBEWithSHA1And" + cipheralgo :
            "PBEWithSHA1And" + cipheralgo + "_" + (keysize * 8);

        if (cipheralgo.equals("DESede")) {
            cipher = new DESedeCipher(provider);
        } else if (cipheralgo.equals("RC2")) {
            cipher = new RC2Cipher(provider);
        } else {
            cipher = new RC4Cipher(provider);
        }
        
        cipher.engineSetMode(mode);
        cipher.engineSetPadding(padding.toString());
        this.keysize = keysize;
    }

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (cipheralgo.equals("DESede") || cipheralgo.equals("RC2")) {
            if ((mode != null) && (!mode.equalsIgnoreCase("CBC"))) {
                throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
            }
        } else if (cipheralgo.equals("RC4")) {
            if ((mode != null) && (!mode.equalsIgnoreCase("ECB"))) {
                throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
            }
        }
    }

    protected void engineSetPadding(String paddingScheme)
        throws NoSuchPaddingException {
        if (cipheralgo.equals("DESede") || cipheralgo.equals("RC2")) {
            if ((paddingScheme != null) &&
                (!paddingScheme.equalsIgnoreCase("PKCS5Padding"))) {
                throw new NoSuchPaddingException("Unsupported padding: " +
                                                paddingScheme);
            }
        } else if (cipheralgo.equals("RC4")) {
            if ((paddingScheme != null) && (!paddingScheme.equalsIgnoreCase("NoPadding"))) {
                throw new NoSuchPaddingException("Unsupported padding: " + paddingScheme);
            }
        }
    }

    protected int engineGetBlockSize() {
        return cipher.engineGetBlockSize();
    }

    protected int engineGetOutputSize(int inputLen) {
        return cipher.engineGetOutputSize(inputLen);
    }

    protected byte[] engineGetIV() {
        return cipher.engineGetIV();
    }

    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params;
        if (iterationCount == 0) {
            this.iterationCount = DEFAULT_ITERATION_COUNT;
        }
        if (salt == null) {
            this.salt = new byte[DEFAULT_SALT_LENGTH];
            provider.getSecureRandom(null).nextBytes(salt);
        }

        PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, iterationCount);
        try {
            params = AlgorithmParameters.getInstance(pbeAlgo, provider);
            params.init(pbeSpec);
        } catch (NoSuchAlgorithmException nsae) {
            // should never happen
            throw new RuntimeException(nsae.getMessage());
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
        } catch (InvalidAlgorithmParameterException e) {
            /* 
             * If initializing the Cipher in Decrypt mode without parameters
             * (neither passed directly or via the key), silence InvalidAlgorithmParameterException
             * to match OpenJDK behavior. 
             */
        }
    }

    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        PBEParameterSpec pspec = null;
        if (params != null) {
            try {
                pspec = params.getParameterSpec(PBEParameterSpec.class);
            } catch (InvalidParameterSpecException e) {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: PBE expected " + e.getMessage());
            }
        }

        engineInit(opmode, key, pspec, random);
    }

    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("SecretKey of PBE type required");
        }

        if (key.getEncoded() == null) {
            throw new InvalidKeyException("Missing password");
        }

        if (!(opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.DECRYPT_MODE ||
                opmode == Cipher.WRAP_MODE || opmode == Cipher.UNWRAP_MODE)) {
            throw new InvalidParameterException("Invalid Cipher mode");
        }

        byte[] keySalt = null;
        int keyIterationCount = 0;
        if (key instanceof javax.crypto.interfaces.PBEKey pkey) {
            keySalt = pkey.getSalt();
            keyIterationCount = pkey.getIterationCount();
        }

        if (params == null) {
            if ((opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) &&
                (keySalt == null || keyIterationCount == 0)) {
                throw new InvalidAlgorithmParameterException("Parameters missing");
            }

            this.iterationCount = (keyIterationCount == 0) ? DEFAULT_ITERATION_COUNT : keyIterationCount;

            this.salt = keySalt == null ? new byte[DEFAULT_SALT_LENGTH] : keySalt;

            if (keySalt == null) {
                provider.getSecureRandom(null).nextBytes(this.salt);
            }
        } else {
            if (params instanceof PBEParameterSpec pbespec) {
                if (keyIterationCount != 0 && (keyIterationCount != pbespec.getIterationCount())) {
                    throw new InvalidAlgorithmParameterException("Different iteration count between key and params");
                }
                this.iterationCount = pbespec.getIterationCount();

                if (keySalt != null && (!Arrays.equals(pbespec.getSalt(), keySalt))) {
                    throw new InvalidAlgorithmParameterException("Inconsistent value of salt between key and params");
                }
                this.salt = pbespec.getSalt();
            } else {
                throw new InvalidAlgorithmParameterException("PBEParameterSpec type required");
            }
        }

        if (salt.length < 8) {
            throw new InvalidAlgorithmParameterException("Salt must be at least 8 bytes long");
        }
        if (iterationCount <= 0) {
            throw new InvalidAlgorithmParameterException("IterationCount must be a positive number");
        }

        byte[] password = key.getEncoded();
        byte[] pass = null, derivedKey = null, iv;
        SecretKey cipherKey;
        try {
            pass = passwordBigEndian(password);
            iv = deriveKey(8, CIPHER_IV, pass);
            derivedKey = deriveKey(keysize, CIPHER_KEY, pass);
            cipherKey = new SecretKeySpec(derivedKey, cipheralgo);
        } finally {
            Arrays.fill(password, (byte) 0x00);
            Arrays.fill(pass, (byte) 0x00);
            Arrays.fill(derivedKey, (byte) 0x00);
        }

        cipher.engineInit(opmode, cipherKey, new IvParameterSpec(iv), random);
    }

    private byte[] passwordBigEndian(byte[] password) {
        if (password.length == 1 && (password[0] & 0x7f) == 0) {
            return new byte[0];
        }
        
        byte[] pass = new byte[(password.length * 2) + 2];
        for (int i = 0, j = 0; i < password.length; i++, j+=2) {
            char passwordChar = (char) (password[i] & 0x7f);
            pass[j] = (byte) ((passwordChar >>> 8) & 0xFF);
            pass[j+1] = (byte) (passwordChar & 0xFF);
        }

        return pass;
    }

    private byte[] deriveKey(int n, int type, byte[] pass) {
        byte[] res = new byte[n];
        MessageDigest sha = new MessageDigest.SHA1(provider);
        int v = 64;
        int u = sha.engineGetDigestLength();
        int c = roundup(n, u) / u;
        byte[] D = new byte[v];
        int s = roundup(this.salt.length, v);
        int p = roundup(pass.length, v);
        byte[] I = new byte[s + p];

        Arrays.fill(D, (byte) type);
        concat(this.salt, I, 0, s);
        concat(pass, I, s, p);

        byte[] Ai;
        byte[] B = new byte[v];

        int i = 0;
        for (; ; i++, n -= u) {
            sha.engineUpdate(D, 0, D.length);
            sha.engineUpdate(I, 0, I.length);
            Ai = sha.engineDigest();
            Ai = sha.PKCS12KeyDeriveHelp(Ai, 0, Ai.length, this.iterationCount);
            System.arraycopy(Ai, 0, res, u * i, Math.min(n, u));
            if (i + 1 == c) {
                break;
            }
            concat(Ai, B, 0, v);
            addOne(v, B);   // add 1 into B

            for (int j = 0; j < I.length; j += v) {
                addTwo(v, B, I, j); // add B into I from j
            }
        }
        Arrays.fill(I, (byte) 0x00);

        return res;
    }

    private static void addOne(int len, byte[] b) {
        for (int i = len - 1; i >= 0; i--) {
            if ((b[i] & 0xff) != 255) {
                b[i]++;
                break;
            } else {
                b[i] = 0;
            }
        }
    }

    // Add src (as integer) to dst from offset (as integer)
    private static void addTwo(int len, byte[] src, byte[] dst, int offset) {
        int carry = 0;
        for (int i = len - 1; i >= 0; i--) {
            int sum = (src[i] & 0xff) + (dst[i + offset] & 0xff) + carry;
            carry = sum >> 8;
            dst[i + offset] = (byte) sum;
        }
    }

    private static int roundup(int x, int y) {
        return ((x + (y - 1)) / y) * y;
    }

    private static void concat(byte[] src, byte[] dst, int start, int len) {
        if (src.length == 0) {
            return;
        }
        int loop = len / src.length;
        int off, i;
        for (i = 0, off = 0; i < loop; i++, off += src.length)
            System.arraycopy(src, 0, dst, off + start, src.length);
        System.arraycopy(src, 0, dst, off + start, len - off);
    }

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return cipher.engineUpdate(input, inputOffset, inputLen);
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
        throws ShortBufferException {
        return cipher.engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException {
        return cipher.engineDoFinal(input, inputOffset, inputLen);
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {
        return cipher.engineDoFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException {
        return cipher.engineWrap(key);
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
                               int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException {
        return cipher.engineUnwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
    }

    public static final class PBEWithSHA1AndDESede extends PBES1Core {
        public PBEWithSHA1AndDESede(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("DESede", "CBC", Padding.PKCS5Padding, 24, provider);
        }
    }

    public static final class PBEWithSHA1AndRC2_40 extends PBES1Core {
        public PBEWithSHA1AndRC2_40(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("RC2", "CBC", Padding.PKCS5Padding, 5, provider);
        }
    }

    public static final class PBEWithSHA1AndRC2_128 extends PBES1Core {
        public PBEWithSHA1AndRC2_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("RC2", "CBC", Padding.PKCS5Padding, 16, provider);
        }
    }

    public static final class PBEWithSHA1AndRC4_40 extends PBES1Core {
        public PBEWithSHA1AndRC4_40(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("RC4", "ECB", Padding.NoPadding, 5, provider);
        }

    }

    public static final class PBEWithSHA1AndRC4_128 extends PBES1Core {
        public PBEWithSHA1AndRC4_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("RC4", "ECB", Padding.NoPadding, 16, provider);
        }
    }
}
