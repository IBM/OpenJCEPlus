/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.AESKeyWrap;
import com.ibm.crypto.plus.provider.ock.OCKException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
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
import javax.crypto.spec.IvParameterSpec;

abstract class AESKeyWrapCipher extends CipherSpi {

    private OpenJCEPlusProvider provider = null;
    private boolean wrappering = true;
    private boolean initialized = false;
    private AESKeyWrap cipher = null;
    private int setKeySize = 0;
    private byte[] buffer = null;
    private int bufSize = 0;
    private int opmode = 0;
    private boolean setPadding = false;
    static final byte[] ICV1 = {
        (byte) 0xA6, (byte) 0xA6, (byte) 0xA6, (byte) 0xA6,
        (byte) 0xA6, (byte) 0xA6, (byte) 0xA6, (byte) 0xA6
    };
    static final byte[] ICV2 = {
        (byte) 0xA6, (byte) 0x59, (byte) 0x59, (byte) 0xA6
    };

    public AESKeyWrapCipher(OpenJCEPlusProvider provider, boolean padding, int keySize) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }
        this.provider = provider;
        this.setKeySize = keySize;
        this.setPadding = padding;
    }

    private void add2Buffer(byte[] data, int offSet, int len) {
        // In NIST SP 800-38F, KWP input size is limited to be no longer
        // than 2^32 bytes. Otherwise, the length cannot be encoded in 32 bits
        // However, given the current spec requirement that recovered text
        // can only be returned after successful tag verification, we are
        // bound by limiting the data size to the size limit of java byte array,
        // e.g. Integer.MAX_VALUE, since all data are returned by doFinal().
        int remain = Integer.MAX_VALUE - bufSize - 16;  //16 bytes required by OCKC call
        if (len > remain) {
            throw new ProviderException("Buffer can only take " +
                remain + " more bytes");
        }

        if (buffer == null || buffer.length - bufSize < len) {
            int newSize = Math.addExact(bufSize, len);

            byte[] temp = new byte[newSize];
            if (buffer != null && bufSize > 0) {
                System.arraycopy(buffer, 0, temp, 0, bufSize);
                Arrays.fill(buffer, (byte) 0x00);
            }
            buffer = temp;
        }

        if (data != null) {
            System.arraycopy(data, offSet, buffer, bufSize, len);
            bufSize += len;
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        
        byte[] out = null;

        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized"); 
        }

        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new IllegalStateException("Cipher not initialized for doFinal");
        }

        if (input == null || inputOffset >= input.length || (input.length < inputLen + inputOffset)) {
            throw new IllegalStateException("Incorrect input to API.");
        }

        add2Buffer(input, inputOffset, inputLen);

        try {
            if (opmode == Cipher.ENCRYPT_MODE) {
                out = cipher.wrap(buffer, 0, bufSize);
            } else {
                out = cipher.unwrap(buffer, 0, bufSize);
            }
        } catch (OCKException ocke) {
            throw new ProviderException("Operation doFinal failed", ocke);
        }
        this.bufSize = 0;
        Arrays.fill(buffer, (byte) 0x00);
        this.buffer = null;
        return out;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] out = null;
        int estOutLen = engineGetOutputSize(inputLen + bufSize);

        if (output.length - outputOffset < estOutLen) {
            throw new ShortBufferException("Need at least " + estOutLen);
        }

        try {
            out = engineDoFinal(input, inputOffset, inputLen);
                            
            if (out.length > estOutLen) {
                throw new AssertionError("Actual output length exceeds estimated length");
            }
            System.arraycopy(out, 0, output, outputOffset, out.length);
            
            return out.length;
        } catch (Exception e) {
            throw e;

        } finally {
            if (out != null) {
                Arrays.fill(out, (byte) 0x00);
            }
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 8;
    }

    @Override
    protected byte[] engineGetIV() {
        byte[] iv = ICV2;
        if (!setPadding) {
            iv = ICV1;
        }
        return iv.clone();
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing.");
        }

        if (!key.getAlgorithm().equalsIgnoreCase("AES")) {
            throw new InvalidKeyException("Key not an AES key.");
        }
        byte[] encoded = key.getEncoded();
        if (!AESUtils.isKeySizeValid(encoded.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + encoded.length + " bytes");
        }
        return encoded.length << 3;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int result = 0;
        if (!wrappering) {
            result = inputLen;
        } else {
            result = Math.addExact(inputLen, 16);
        }
        return (result < 0? 0:result);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;
        try {
            params = AlgorithmParameters.getInstance("AES");
            params.init(new IvParameterSpec(engineGetIV()));
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            // should never happen
            throw new AssertionError();
        }
        return params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

        if (opmode == Cipher.UNWRAP_MODE || opmode == Cipher.DECRYPT_MODE) {
            wrappering = false;
        } else if (opmode == Cipher.WRAP_MODE || opmode == Cipher.ENCRYPT_MODE) {
            wrappering = true;
        } else {
            throw new InvalidParameterException("Incorrect opmode passed in");
        }
        
        this.opmode = opmode;
        internalInit(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("This cipher " +
                "does not accept any parameters");
        }
        engineInit(opmode, key, random);
    }

    private void internalInit(int opmode, Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("AES"))) {
            throw new InvalidKeyException("Wrong algorithm: AES required");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("Key bytes are missing");
        }

        if (!checkKeySize(rawKey.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + rawKey.length + " bytes");
        }

        try {
            this.cipher = new AESKeyWrap(provider.getOCKContext(), rawKey, setPadding);
        } catch (Exception e) {
            throw new InvalidKeyException("OCKC context null or bad key.", e);
        } 
        this.initialized = true;   
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode == null || (!mode.equalsIgnoreCase("KW") && !mode.equalsIgnoreCase("KWP"))) {
            throw new NoSuchAlgorithmException("Only KW or KWP mode is supported.");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException(padding + " can not be used.");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized"); 
        }

        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new IllegalStateException("Cipher not initialized for update");
        }

        add2Buffer(input, inputOffset, inputLen);
        return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized"); 
        }

        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE) {
            throw new IllegalStateException("Cipher not initialized for update");
        }

        add2Buffer(input, inputOffset, inputLen);
        return 0;
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        checkCipherInitialized();
        if (!wrappering) {
            throw new IllegalStateException("Cipher not initialized for wrap");
        }

        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }

        try {
            return cipher.wrap(encoded, 0, encoded.length);
        } catch (Exception e) {
            // should not occur
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        checkCipherInitialized();

        if (wrappering) {
            throw new IllegalStateException("Cipher not initialized for unwrap");
        }
        try {
            byte[] encoded = cipher.unwrap(wrappedKey, 0, wrappedKey.length);
            return ConstructKeys.constructKey(provider, encoded, algorithm, type);
        } catch (Exception e) {
            // should not occur
            throw new InvalidKeyException("Unwrapping failed", e);
        }    
    }

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }

    private boolean checkKeySize(int keySize) {
        if ((!AESUtils.isKeySizeValid(keySize) || (keySize != setKeySize)) && (setKeySize != -1)) {
            return false;
        }
        return true;
    }
    public static final class KW extends AESKeyWrapCipher {

        public KW(OpenJCEPlusProvider provider) {
            super(provider, false, -1);
        }
    }

    public static final class KWP extends AESKeyWrapCipher {

        public KWP(OpenJCEPlusProvider provider) {
            super(provider, true, -1);
        }
    }
    
    public static final class KW_128 extends AESKeyWrapCipher {

        public KW_128(OpenJCEPlusProvider provider) {
            super(provider, false, 16);
        }
    }

    public static final class KWP_128 extends AESKeyWrapCipher {

        public KWP_128(OpenJCEPlusProvider provider) {
            super(provider, true, 16);
        }
    }
        
    public static final class KW_192 extends AESKeyWrapCipher {

        public KW_192(OpenJCEPlusProvider provider) {
            super(provider, false, 24);
        }
    }

    public static final class KWP_192 extends AESKeyWrapCipher {

        public KWP_192(OpenJCEPlusProvider provider) {
            super(provider, true, 24);
        }
    }
        
    public static final class KW_256 extends AESKeyWrapCipher {

        public KW_256(OpenJCEPlusProvider provider) {
            super(provider, false, 32);
        }
    }

    public static final class KWP_256 extends AESKeyWrapCipher {

        public KWP_256(OpenJCEPlusProvider provider) {
            super(provider, true, 32);
        }
    }
}
