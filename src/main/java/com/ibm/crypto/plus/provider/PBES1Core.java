/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKException;
import com.ibm.crypto.plus.provider.ock.PBES1;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
import javax.crypto.ShortBufferException;
import javax.crypto.spec.PBEParameterSpec;

abstract class PBES1Core extends CipherSpi {
    private final String pbeAlgo;
    private int opmode;
    private int is_en;
    private int iterationCount = 0;
    protected int blksize;
    private byte[] salt = null;
    private byte[] password;
    private ByteArrayOutputStream buffer;
    private OpenJCEPlusProvider provider = null;

    private static final byte DES_BLOCK_SIZE = 8;
    private static final byte RC4_BLOCK_SIZE = 0;
    private static final int DEFAULT_ITERATION_COUNT = 1024;
    private static final int DEFAULT_ITERATION_COUNT_MD5AndDES = 10;
    private static final int DEFAULT_SALT_LENGTH = 20;
    private static final int DEFAULT_SALT_LENGTH_MD5AndDES = 8;
    private static final int MAX_BUFFER_SIZE = Integer.MAX_VALUE - 16;

    PBES1Core(String alogrithm, OpenJCEPlusProvider provider, String mode, String padding)
        throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.provider = provider;
        this.pbeAlgo = alogrithm;
        this.blksize = DES_BLOCK_SIZE;
        engineSetMode(mode);
        engineSetPadding(padding);
        buffer = new ByteArrayOutputStream();
    }

    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if ((mode != null) && (!mode.equalsIgnoreCase("CBC"))) {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
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
        return blksize;
    }

    protected int engineGetOutputSize(int inputLen) {
        int outputLen;
        int buffered = buffer.size() % blksize;
        if (buffered == 0) {
            outputLen = inputLen;
        } else {
            outputLen = Math.addExact(buffered, inputLen);
        }

        if (opmode == Cipher.ENCRYPT_MODE && blksize != RC4_BLOCK_SIZE) {
            if (outputLen < blksize) {
                outputLen = blksize;
            } else {
                int remainder = (outputLen - blksize) % blksize;
                outputLen = Math.addExact(outputLen, (blksize - remainder));
            }
        }
        
        return outputLen;
    }

    protected byte[] engineGetIV() {
        throw new UnsupportedOperationException("IV is set in the native code and is inaccessible by the user");
    }

    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params;
        if (iterationCount == 0) {
            this.iterationCount = pbeAlgo.equals("PBEWithMD5AndDES") ? DEFAULT_ITERATION_COUNT_MD5AndDES :
                DEFAULT_ITERATION_COUNT;
        }
        if (salt == null) {
            this.salt = pbeAlgo.equals("PBEWithMD5AndDES") ? new byte[DEFAULT_SALT_LENGTH_MD5AndDES] :
                new byte[DEFAULT_SALT_LENGTH];
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
            // should never happen
            throw new InvalidKeyException("PBE parameters cannot be generated", e);
        }
    }

    protected void engineInit(int opmode, Key key,
                              AlgorithmParameterSpec params,
                              SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Provided key is null");
        }
        this.password = key.getEncoded();
        if (this.password == null) {
            throw new InvalidKeyException("Missing password");
        }

        if (!(opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.DECRYPT_MODE ||
                opmode == Cipher.WRAP_MODE || opmode == Cipher.UNWRAP_MODE)) {
            throw new InvalidParameterException("Invalid Cipher mode");
        }
        this.opmode = opmode;
        this.is_en = (this.opmode == Cipher.ENCRYPT_MODE || this.opmode == Cipher.WRAP_MODE) ? 1 : 0;

        byte[] keySalt = null;
        int keyIterationCount = 0;
        if (key instanceof javax.crypto.interfaces.PBEKey) {
            javax.crypto.interfaces.PBEKey pkey = (javax.crypto.interfaces.PBEKey) key;
            keySalt = pkey.getSalt();
            keyIterationCount = pkey.getIterationCount();
        }

        if (params == null) {
            if ((this.opmode == Cipher.DECRYPT_MODE || this.opmode == Cipher.UNWRAP_MODE) &&
                (keySalt == null || keyIterationCount == 0)) {
                throw new InvalidAlgorithmParameterException("Parameters missing");
            }

            this.iterationCount = (keyIterationCount == 0) ? (pbeAlgo.equals("PBEWithMD5AndDES") ? 
                    DEFAULT_ITERATION_COUNT_MD5AndDES : DEFAULT_ITERATION_COUNT) : keyIterationCount;

            this.salt = keySalt == null ? (pbeAlgo.equals("PBEWithMD5AndDES") ? 
                    new byte[DEFAULT_SALT_LENGTH_MD5AndDES] : new byte[DEFAULT_SALT_LENGTH]) : keySalt;

            if (keySalt == null) {
                provider.getSecureRandom(null).nextBytes(this.salt);
            }
        } else {
            if (params instanceof PBEParameterSpec) {
                PBEParameterSpec pbespec = (PBEParameterSpec) params;
                if (keyIterationCount != 0 && (keyIterationCount != pbespec.getIterationCount())) {
                    throw new InvalidAlgorithmParameterException("Different iteration count between key and params");
                }
                this.iterationCount = pbespec.getIterationCount();

                if (keySalt != null && (!Arrays.equals(pbespec.getSalt(), keySalt))) {
                    throw new InvalidAlgorithmParameterException("Different salt between key and params");
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

    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        validateCipher(inputLen, false, -1);
        writeToBuffer(input, inputOffset, inputLen);

        return new byte[0];
    }

    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
                               byte[] output, int outputOffset)
        throws ShortBufferException {
        if ((this.engineGetOutputSize(inputLen) + outputOffset) > output.length) {
            throw new ShortBufferException("Output buffer must be (at least) " + this.engineGetOutputSize(inputLen) + " bytes long");
        }

        this.engineUpdate(input, inputOffset, inputLen);
        return 0;
    }

    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException {

        validateCipher(inputLen, false, -1);
        writeToBuffer(input, inputOffset, inputLen);

        if ((this.opmode == Cipher.DECRYPT_MODE && buffer.size() == 0) ||
                (this.opmode == Cipher.ENCRYPT_MODE && buffer.size() == 0 && blksize == 0)) {
            return new byte[0];
        }

        try {
            input = buffer.toByteArray();
            buffer.reset();
            return PBES1.PBEdoFinal(provider.getOCKContext(), pbeAlgo, password, salt, input, iterationCount, is_en);
        } catch (OCKException e) {
            throw new IllegalBlockSizeException("Unable to process input data" + e.getMessage());
        }
    }

    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
                                byte[] output, int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException,
               BadPaddingException {

        validateCipher(inputLen, false, -1);
        writeToBuffer(input, inputOffset, inputLen);
        
        if ((this.opmode == Cipher.DECRYPT_MODE && buffer.size() == 0) ||
                (this.opmode == Cipher.ENCRYPT_MODE && buffer.size() == 0 && blksize == 0)) {
            return 0;
        }

        byte res[] = null;
        try {
            input = buffer.toByteArray();
            buffer.reset();
            res = PBES1.PBEdoFinal(provider.getOCKContext(), pbeAlgo, password, salt, input, iterationCount, is_en);
            if (outputOffset + res.length > output.length) {
                throw new ShortBufferException("Output buffer must be (at least) " + res.length + " bytes long");
            }
            System.arraycopy(res, 0, output, outputOffset, res.length);
        } catch (OCKException e) {
            throw new IllegalBlockSizeException("Unable to process input data" + e.getMessage());
        }

        return res.length;
    }

    protected byte[] engineWrap(Key key)
        throws IllegalBlockSizeException, InvalidKeyException {

        validateCipher(-1, true, Cipher.WRAP_MODE);

        byte[] result = null;
        byte[] encodedKey = null;
        try {
            encodedKey = key.getEncoded();
            if ((encodedKey == null) || (encodedKey.length == 0)) {
                throw new InvalidKeyException("Cannot get an encoding of " +
                                              "the key to be wrapped");
            }

            result = PBES1.PBEdoFinal(provider.getOCKContext(), pbeAlgo, password, salt, encodedKey, iterationCount, is_en);
        } catch (OCKException e) {
            throw new IllegalBlockSizeException("Unable to process key" + e.getMessage());
        }  finally {
            Arrays.fill(encodedKey, (byte) 0x00);
        }

        return result;
    }

    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
                               int wrappedKeyType)
        throws InvalidKeyException, NoSuchAlgorithmException {

        validateCipher(-1, true, Cipher.UNWRAP_MODE);

        try {
            byte[] encodedKey = PBES1.PBEdoFinal(provider.getOCKContext(), pbeAlgo, password, salt, wrappedKey, iterationCount, is_en);
            try {
                return ConstructKeys.constructKey(provider, encodedKey, wrappedKeyAlgorithm, wrappedKeyType);
            } finally {
                Arrays.fill(encodedKey, (byte) 0x00);
            }
        } catch (OCKException e) {
            throw new InvalidKeyException("Unable to process encoded key" + e.getMessage());
        }
    }

    private void validateCipher(int inputLen, boolean wrap, int mode) {
        if (this.salt == null || iterationCount == 0) {
            throw new IllegalStateException("Cipher not initialized");
        }
        if (wrap) {
            if (this.opmode != mode) {
                throw new IllegalStateException("Cipher is not initialized with the correct mode");
            }
        } else {
            if (!(this.opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.DECRYPT_MODE)) {
                throw new IllegalStateException("Cipher is not initialized with the correct mode");
            }
            if ((buffer.size() + inputLen) > MAX_BUFFER_SIZE) {
                throw new IllegalArgumentException("The input data stream exceeded the buffer size");
            }
        }
    }

    private void writeToBuffer(byte[] input, int inputOffset, int inputLen) {
        try {
            if (input != null && inputLen > 0) {
                this.buffer.write(Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen));
            }
        } catch (IOException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static final class PBEWithMD5AndDES extends PBES1Core {
        public PBEWithMD5AndDES(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithMD5AndDES", provider, "CBC", "PKCS5Padding");
        }
    }

    public static final class PBEWithSHA1AndDESede extends PBES1Core {
        public PBEWithSHA1AndDESede(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithSHA1AndDESede", provider, "CBC", "PKCS5Padding");
        }
    }

    public static final class PBEWithSHA1AndRC2_40 extends PBES1Core {
        public PBEWithSHA1AndRC2_40(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithSHA1AndRC2_40", provider, "CBC", "PKCS5Padding");
        }
    }

    public static final class PBEWithSHA1AndRC2_128 extends PBES1Core {
        public PBEWithSHA1AndRC2_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithSHA1AndRC2_128", provider, "CBC", "PKCS5Padding");
        }
    }

    static sealed class RC4Cipher extends PBES1Core {
        public RC4Cipher(String algorithm, OpenJCEPlusProvider provider, String mode, String padding) 
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(algorithm, provider, mode, padding);
            this.blksize = RC4_BLOCK_SIZE;
        }

        @Override
        protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
            if ((mode != null) && (!mode.equalsIgnoreCase("ECB"))) {
                throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
            }
        }

        @Override
        protected void engineSetPadding(String paddingScheme)
            throws NoSuchPaddingException {  
            if ((paddingScheme != null) && (!paddingScheme.equalsIgnoreCase("NoPadding"))) {
                throw new NoSuchPaddingException("Unsupported padding: " + paddingScheme);
            }
        }

        @Override
        protected int engineGetOutputSize(int inputLen) {
            return inputLen;
        }
        
    }

    public static final class PBEWithSHA1AndRC4_40 extends RC4Cipher {
        public PBEWithSHA1AndRC4_40(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithSHA1AndRC4_40", provider, "ECB", "NoPadding");
        }

    }

    public static final class PBEWithSHA1AndRC4_128 extends RC4Cipher {
        public PBEWithSHA1AndRC4_128(OpenJCEPlusProvider provider)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithSHA1AndRC4_128", provider, "ECB", "NoPadding");
        }
    }
}
