/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.OCKException;
import com.ibm.crypto.plus.provider.base.SymmetricCipher;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

/*
 * OpenJCEPlus doesn't support RC4 Ciphers. This class
 * is only used for PBES1 algorithms.
 */
public final class RC4Cipher extends LegacyCipher {

    private OpenJCEPlusProvider provider = null;
    private SymmetricCipher symmetricCipher = null;
    private boolean encrypting = true;
    private boolean initialized = false;

    static private final int RC4_BLOCK_SIZE = 8;

    public RC4Cipher(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];

            int outputLen = symmetricCipher.doFinal(input, inputOffset, inputLen, output, 0);
            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }
                return out;
            } else {
                return output;
            }
        } catch (ShortBufferException ock_sbe) {
            // should not occur
            throw provider.providerException("Failure in engineDoFinal", ock_sbe);
        } catch (OCKException e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            return symmetricCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
        } catch (OCKException e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return RC4_BLOCK_SIZE;
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        throw new UnsupportedOperationException("Method engineGetKeySize " +
            "is not supported for RC4Cipher class");
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        try {
            return symmetricCipher.getOutputSize(inputLen);
        } catch (Exception e) {
            throw provider.providerException("Unable to get output size", e);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException("Method engineGetParameters " +
            "is not supported for RC4Cipher class");
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new UnsupportedOperationException("Method engineInit for RC4Cipher class" +
            "is only supported when AlgorithmParameterSpec is passed as a parameter");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        internalInit(opmode, key);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Method engineInit for RC4Cipher class" +
            "is only supported when AlgorithmParameterSpec is passed as a parameter");
    }

    private void internalInit(int opmode, Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("RC4"))) {
            throw new InvalidKeyException("Wrong algorithm: RC4 required");
        }

        if (!(key.getFormat().equalsIgnoreCase("RAW"))) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("RAW bytes missing");
        }

        if (!isKeySizeValid(rawKey.length)) {
            Arrays.fill(rawKey, (byte) 0x00);
            throw new InvalidKeyException("Invalid RC4 key length: " + rawKey.length + " bytes");
        }

        boolean isEncrypt = (opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE);

        try {
            if (symmetricCipher == null) {
                symmetricCipher = SymmetricCipher.getInstanceRC4(provider.getOCKContext(), rawKey.length, provider);
            }

            if (isEncrypt) {
                symmetricCipher.initCipherEncrypt(rawKey, null);
            } else {
                symmetricCipher.initCipherDecrypt(rawKey, null);
            }

            this.encrypting = isEncrypt;
            this.initialized = true;
        } catch (Exception e) {
            throw provider.providerException("Failed to init cipher", e);
        } finally {
            Arrays.fill(rawKey, (byte) 0x00);
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        String modeUpperCase = mode.toUpperCase();
        if (!modeUpperCase.equals("ECB")) {
            throw new NoSuchAlgorithmException("Cipher mode: " + mode + " not found");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkCipherInitialized();

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];

            int outputLen = symmetricCipher.update(input, inputOffset, inputLen, output, 0);
            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }
                return out;
            } else {
                return output;
            }
        } catch (BadPaddingException ock_bpe) {
            // should not occur
            throw provider.providerException("Failure in engineUpdate", ock_bpe);
        } catch (ShortBufferException ock_sbe) {
            // should not occur
            throw provider.providerException("Failure in engineUpdate", ock_sbe);
        } catch (OCKException e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        checkCipherInitialized();

        try {
            return symmetricCipher.update(input, inputOffset, inputLen, output, outputOffset);
        } catch (BadPaddingException ock_bpe) {
            // should not occur
            throw provider.providerException("Failure in engineDoFinal", ock_bpe);
        } catch (OCKException e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        checkCipherInitialized();

        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }

        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        checkCipherInitialized();

        try {
            byte[] encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return ConstructKeys.constructKey(provider, encoded, algorithm, type);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Unwrapping failed", e);
        } catch (IllegalBlockSizeException e) {
            // should not occur, handled with length check above
            throw new InvalidKeyException("Unwrapping failed", e);
        }
    }

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }

    private boolean isKeySizeValid(int len) {
        return (len == 16 || len == 5);
    }
}
