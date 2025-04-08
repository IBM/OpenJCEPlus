/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.Padding;
import com.ibm.crypto.plus.provider.ock.SymmetricCipher;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
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
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;

public final class ChaCha20Cipher extends CipherSpi implements ChaCha20Constants {

    private OpenJCEPlusProvider provider = null;
    private SymmetricCipher symmetricCipher = null;
    private Padding padding = Padding.NoPadding;
    private byte[] ivBytes = null;
    private byte[] keyBytes = null;
    private byte[] nonceBytes = null;
    private int counter = 0;
    private boolean encrypting = false;
    private boolean initialized = false;
    private SecureRandom random = null;

    public ChaCha20Cipher(OpenJCEPlusProvider provider) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this.getClass())) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }
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
        } catch (BadPaddingException ock_bpe) {
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        } finally {
            resetVars();
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        checkCipherInitialized();

        try {
            int ret = symmetricCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
            return ret;
        } catch (BadPaddingException ock_bpe) {
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {

            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        } finally {
            resetVars();
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return ChaCha20_BLOCK_SIZE;
    }

    @Override
    protected byte[] engineGetIV() {
        return (this.nonceBytes == null) ? null : this.nonceBytes.clone();
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (encoded.length != ChaCha20_KEY_SIZE) {
            throw new InvalidKeyException("Key must be " + ChaCha20_KEY_SIZE + " bytes");
        }

        return encoded.length << 3;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int outputLen = inputLen;
        return outputLen;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters chaCha20Params = null;

        return chaCha20Params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.initialized = false;

        if (opmode == Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("Parameters missing");
        }

        internalInit(opmode, key, generateRandomNonce(random), 1);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.initialized = false;

        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            if (params instanceof ChaCha20ParameterSpec) {
                byte[] nonce = ((ChaCha20ParameterSpec) params).getNonce();
                if (nonce.length != ChaCha20_NONCE_SIZE) {
                    throw new InvalidAlgorithmParameterException(
                            "Nonce must be " + ChaCha20_NONCE_SIZE + " bytes");
                }
                int counter = ((ChaCha20ParameterSpec) params).getCounter();
                internalInit(opmode, key, nonce, counter);
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Wrong parameter type: ChaCha20ParameterSpec expected");
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.initialized = false;

        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
        }
    }

    private void internalInit(int opmode, Key newKey, byte[] newNonceBytes, int newCounter)
            throws InvalidKeyException {
        if ((opmode == Cipher.WRAP_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            throw new UnsupportedOperationException("WRAP_MODE and UNWRAP_MODE are not supported");
        } else if ((opmode != Cipher.ENCRYPT_MODE) && (opmode != Cipher.DECRYPT_MODE)) {
            throw new InvalidKeyException("Unknown opmode: " + opmode);
        }

        if (newKey == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(newKey.getAlgorithm().equalsIgnoreCase("ChaCha20"))) {
            throw new InvalidKeyException("Wrong algorithm: ChaCha20 required");
        }

        if (!(newKey.getFormat().equalsIgnoreCase("RAW"))) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }

        byte[] newKeyBytes = newKey.getEncoded();
        if (newKeyBytes == null) {
            throw new InvalidKeyException("RAW bytes missing");
        }

        if (newKeyBytes.length != ChaCha20_KEY_SIZE) {
            throw new InvalidKeyException("Key must be " + ChaCha20_KEY_SIZE + " bytes");
        }
        boolean isEncrypt = (opmode == Cipher.ENCRYPT_MODE);
        this.encrypting = isEncrypt;

        if (isEncrypt) {
            checkKeyAndNonce(newKeyBytes, newNonceBytes);
        }

        byte[] newIvBytes = ByteBuffer.allocate(ChaCha20_IV_SIZE).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(newCounter).put(newNonceBytes).array();

        try {
            if (symmetricCipher == null) {
                symmetricCipher = SymmetricCipher.getInstanceChaCha20(provider.getOCKContext(),
                        padding);
            }

            if (isEncrypt) {
                symmetricCipher.initCipherEncrypt(newKeyBytes, newIvBytes);
            } else {
                symmetricCipher.initCipherDecrypt(newKeyBytes, newIvBytes);
            }

            this.keyBytes = newKeyBytes;
            this.nonceBytes = newNonceBytes;
            this.counter = newCounter;
            this.ivBytes = newIvBytes;
            this.initialized = true;
        } catch (Exception e) {
            throw provider.providerException("Failed to init cipher", e);
        }

    }

    private void checkKeyAndNonce(byte[] newKeyBytes, byte[] newNonce) throws InvalidKeyException {

        // A new initialization must have either a different key or nonce
        // so the starting state for each block is not the same as the
        // previous initialization.

        if (MessageDigest.isEqual(newKeyBytes, this.keyBytes)
                && MessageDigest.isEqual(newNonce, this.nonceBytes)) {
            throw new InvalidKeyException("Matching key and nonce from previous initialization");
        }
    }

    private boolean checkKeyAndNonce(byte[] curKeyBytes, byte[] curNonce, byte[] lastKeyBytes,
            byte[] lastNonce) {

        // A new initialization must have either a different key or nonce
        // so the starting state for each block is not the same as the
        // previous initialization.
        boolean equalFlag = false;

        if (MessageDigest.isEqual(curKeyBytes, lastKeyBytes)
                && MessageDigest.isEqual(curNonce, lastNonce)) {
            equalFlag = true;
        }

        return equalFlag;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode.equalsIgnoreCase("None") == false) {
            throw new NoSuchAlgorithmException("Mode must be None");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (padding.equalsIgnoreCase("NoPadding")) {
            this.padding = Padding.NoPadding;
        } else {
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
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {

        checkCipherInitialized();

        try {
            return symmetricCipher.update(input, inputOffset, inputLen, output, outputOffset);
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        throw new IllegalStateException("Cipher is running in non-AEAD mode");
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src) {
        throw new IllegalStateException("Cipher is running in non-AEAD mode");
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        throw new UnsupportedOperationException("WRAP_MODE and UNWRAP_MODE are not supported");
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("WRAP_MODE and UNWRAP_MODE are not supported");
    }

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }

    // Reset class variables.
    private void resetVars() {
        this.initialized = (!this.encrypting); // force re-initialization only when encrypting
    }

    private byte[] generateRandomNonce(SecureRandom random) {
        this.random = (random != null) ? random : provider.getSecureRandom(random);
        byte[] generatedNonce = new byte[ChaCha20_NONCE_SIZE];
        random.nextBytes(generatedNonce);

        return generatedNonce;
    }
}
