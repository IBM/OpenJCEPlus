/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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

    // Java 8 Cipher.class documentation does not require that a cipher.init is
    // called between successive encryption or decryption. However, it requires
    // prior IV+ Key cannot be used. Since it is not feasible to maintain a history 
    // of previously called IV+Key combination, this implementation checks the 
    // previous encryption. The exception to this requirement is when
    // an SBE was encountered, the Cipher class allows same IV and Key but with a
    // larger buffer.
    // Calling encryption/decryption after a sbe is allowed which allows applications
    // to call failed operation with a larger buffer
    // This implementation deviates from Sun's implementation.

    private byte[] lastEncKey = null; //last encryption Key
    private byte[] lastEncNonce = null; // last encryption Nonce

    // Keeps track if a shortBufferException was experienced in last call. 
    private boolean sbeInLastFinalEncrypt = false;

    private boolean initCalledInEncSeq = false;
    private boolean generateIV = false;
    SecureRandom random = null;

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

        // Generate IV only when Init was not called in this seq and an init was called
        // during prior encryption without specifying params.
        if ((!initCalledInEncSeq) && (!sbeInLastFinalEncrypt) && (generateIV) && (encrypting)) {
            this.nonceBytes = generateRandomNonce(random).clone();
            this.counter = this.counter + 1;
        }

        // The checks are performed only for successive encryption, and when Init
        // operation was not called
        // since iv must not be changed between encryption and decryption.
        // performing two successive decryption with the same IV + Key is allowed.
        if ((!initCalledInEncSeq) && (!sbeInLastFinalEncrypt) && (encrypting)) {
            boolean sameKeyIv = checkKeyAndNonce(keyBytes, nonceBytes, lastEncKey, lastEncNonce);
            if (sameKeyIv) {
                resetVarsAfterException();
                throw new IllegalStateException("Cannot reuse iv for ChaCha20Poly1305 encryption");
            }
        }

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];

            int outputLen = symmetricCipher.doFinal(input, inputOffset, inputLen, output, 0);
            initCalledInEncSeq = false;
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
            resetVarsAfterException();
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            resetVarsAfterException();
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (Exception e) {
            resetVarsAfterException();
            throw provider.providerException("Failure in engineDoFinal", e);
        } finally {
            if (encrypting) {
                lastEncKey = keyBytes.clone();
                lastEncNonce = nonceBytes.clone();
            }
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        checkCipherInitialized();

        // Generate IV only when Init was not called in this seq and an init was called during prior encryption
        // without specifying params.
        if ((!initCalledInEncSeq) && (!sbeInLastFinalEncrypt) && (generateIV) && (encrypting)) {
            this.nonceBytes = generateRandomNonce(random).clone();
            this.counter = this.counter + 1;
        }

        // The checks are performed only for successive encryption, and when Init operation was not called
        // since iv must not be changed between encryption and decryption.
        // performing two successive decryption with the same IV + Key is allowed.
        if ((!initCalledInEncSeq) && (!sbeInLastFinalEncrypt) && (encrypting)) {
            boolean sameKeyIv = checkKeyAndNonce(keyBytes, nonceBytes, lastEncKey, lastEncNonce);
            if (sameKeyIv) {
                resetVarsAfterException();
                throw new IllegalStateException("Cannot reuse iv for ChaCha20Poly1305 encryption");
            }
        }

        try {
            int ret = symmetricCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
            sbeInLastFinalEncrypt = false;
            this.initCalledInEncSeq = false;
            return ret;
        } catch (BadPaddingException ock_bpe) {
            resetVarsAfterException();
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            resetVarsAfterException();

            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            sbeInLastFinalEncrypt = encrypting;
            throw sbe;
        } catch (Exception e) {

            resetVarsAfterException();
            throw provider.providerException("Failure in engineDoFinal", e);
        } finally {
            // Do not reset this.initialized in final block
            // Calling applications can decrypt or encrypt after a successful completion.
            // Only IV need to change for Encryption
            // Save Keys and Nonce only for encryption. applications must be able to call decrypt after 
            // an encrypt with the same key and iv
            if (encrypting) {
                lastEncKey = keyBytes.clone();
                lastEncNonce = nonceBytes.clone();
            }
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

        if (opmode == Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("Parameters missing");
        }
        this.random = random;
        this.initialized = false;
        this.sbeInLastFinalEncrypt = false;
        generateIV = (opmode == Cipher.ENCRYPT_MODE);

        internalInit(opmode, key, generateRandomNonce(random), 1);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.initialized = false;
        this.sbeInLastFinalEncrypt = false;
        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            generateIV = false; // Use IV from params
            this.random = random;

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

        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
        }
    }

    private void internalInit(int opmode, Key newKey, byte[] newNonceBytes, int newCounter)
            throws InvalidKeyException {

        this.initialized = false;
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
            this.initCalledInEncSeq = isEncrypt;
        } catch (Exception e) {
            this.initialized = false;
            this.initCalledInEncSeq = false;
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

    // Reset class variables after an exception
    private void resetVarsAfterException() {
        // force re-initialization presumably with different nonce and key
        this.initialized = false;
        this.sbeInLastFinalEncrypt = false;
        this.initCalledInEncSeq = false;
    }

    private byte[] generateRandomNonce(SecureRandom random) {
        SecureRandom rand = (random != null) ? random : new SecureRandom();
        SecureRandom cryptoRandom = provider.getSecureRandom(rand);
        byte[] generatedNonce = new byte[ChaCha20_NONCE_SIZE];
        cryptoRandom.nextBytes(generatedNonce);

        return generatedNonce;
    }
}
