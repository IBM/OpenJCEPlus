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
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

public final class AESCipher extends CipherSpi implements AESConstants {

    private OpenJCEPlusProvider provider = null;
    private SymmetricCipher symmetricCipher = null;
    private String mode = "ECB";
    private Padding padding = Padding.PKCS5Padding;
    private byte[] iv = null;
    private boolean encrypting = true;
    private boolean initialized = false;
    private int buffered = 0;
    private byte[] buffer = null;
    private boolean use_z_fast_command;
    private static int isHardwareSupport = 0;
    private SecureRandom cryptoRandom = null;

    public AESCipher(OpenJCEPlusProvider provider) {
        buffer = new byte[engineGetBlockSize() * 3];
        this.provider = provider;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];
            int outputLen = engineDoFinal(input, inputOffset, inputLen, output, 0);

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
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            if (use_z_fast_command) {
                int encryptedData = engineUpdate(input, inputOffset, inputLen, output,
                        outputOffset);
                outputOffset += encryptedData;
                int totalLen = buffered;
                int paddedLen = totalLen;
                if (padding != Padding.NoPadding && encrypting) {
                    int paddingLen = 16 - (totalLen % 16);
                    paddedLen += paddingLen;
                    padWithLen(buffer, totalLen, paddingLen);
                }

                if ((output == null) || (((output.length - outputOffset) < paddedLen)
                        && (encrypting || padding == Padding.NoPadding)))
                    throw new ShortBufferException(
                            "Output buffer too short: " + (output.length - outputOffset)
                                    + " bytes given, " + paddedLen + " bytes needed");

                if (paddedLen % 16 != 0) {
                    if (padding == Padding.PKCS5Padding) {
                        throw new IllegalBlockSizeException(
                                "Input length (with padding) not multiple of 16 bytes");
                    } else {
                        throw new IllegalBlockSizeException(
                                "Input length not multiple of 16 bytes");
                    }
                }

                if (paddedLen == 0) {
                    totalLen = 0;
                } else {
                    totalLen = symmetricCipher.z_doFinal(buffer, 0, paddedLen, output,
                            outputOffset);
                }
                // totalLen = finalNoPadding(buffer, 0, output, outputOffset, paddedLen);
                symmetricCipher.resetParams();

                if (padding != Padding.NoPadding && !encrypting) { // get rid of padding bytes
                    int padStart = unpad(output, outputOffset, totalLen);
                    if (padStart < 0)
                        throw new BadPaddingException("Given final block not properly padded");
                    totalLen = padStart - outputOffset;

                    if ((output.length - outputOffset) < totalLen)
                        throw new ShortBufferException(
                                "Output buffer too short: " + (output.length - outputOffset)
                                        + " bytes given, " + totalLen + " bytes needed");
                }
                buffered = 0;

                encryptedData += totalLen;
                return encryptedData;
            } else {
                return symmetricCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
            }
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
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return AES_BLOCK_SIZE;
    }

    @Override
    protected byte[] engineGetIV() {
        return (this.iv == null) ? null : this.iv.clone();
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (!AESUtils.isKeySizeValid(encoded.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + encoded.length + " bytes");
        }
        return encoded.length << 3;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        try {
            if (use_z_fast_command) {
                return getOutputSizeForZ(inputLen);
            } else {
                return symmetricCipher.getOutputSize(inputLen);
            }
        } catch (Exception e) {
            throw provider.providerException("Unable to get output size", e);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;

        if (this.iv != null) {
            IvParameterSpec ivSpec = new IvParameterSpec(this.iv);
            try {
                params = AlgorithmParameters.getInstance("AES", provider);
                params.init(ivSpec);
            } catch (NoSuchAlgorithmException nsae) {
                throw new ProviderException("Cannot find AES AlgorithmParameters implementation in "
                        + provider.getName() + " provider");
            } catch (InvalidParameterSpecException ipse) {
                // should never happen
                throw new ProviderException(ivSpec.getClass() + " not supported");
            }
        }

        return params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (mode.equals("ECB")) {
            internalInit(opmode, key, null);
            return;
        }

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            throw new InvalidKeyException("Parameters missing");
        }

        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }
        byte[] generatedIv = new byte[AES_BLOCK_SIZE];
        cryptoRandom.nextBytes(generatedIv);

        internalInit(opmode, key, generatedIv);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            if (params instanceof IvParameterSpec) {
                byte[] iv = ((IvParameterSpec) params).getIV();
                if (iv.length != AES_BLOCK_SIZE) {
                    throw new InvalidAlgorithmParameterException(
                            "IV must be " + AES_BLOCK_SIZE + " bytes");
                }
                internalInit(opmode, key, iv);
            } else {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        IvParameterSpec ivSpec = null;

        if (params != null) {
            try {
                ivSpec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            }
        }

        engineInit(opmode, key, ivSpec, random);
    }

    private void internalInit(int opmode, Key key, byte[] iv) throws InvalidKeyException {
        buffered = 0;
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("AES"))) {
            throw new InvalidKeyException("Wrong algorithm: AES required");
        }

        if (!(key.getFormat().equalsIgnoreCase("RAW"))) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("RAW bytes missing");
        }

        if (!AESUtils.isKeySizeValid(rawKey.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + rawKey.length + " bytes");
        }

        try {
            if ((symmetricCipher == null) || (symmetricCipher.getKeyLength() != rawKey.length)) {
                symmetricCipher = SymmetricCipher.getInstanceAES(provider.getOCKContext(), mode,
                        padding, rawKey.length);
                // Check whether used algorithm is CBC and whether hardware supports is available
                use_z_fast_command = symmetricCipher.getHardwareSupportStatus();
            }

            boolean isEncrypt = (opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE);
            if (isEncrypt) {
                symmetricCipher.initCipherEncrypt(rawKey, iv);
            } else {
                symmetricCipher.initCipherDecrypt(rawKey, iv);
            }

            this.iv = iv;
            this.encrypting = isEncrypt;
            this.initialized = true;
        } catch (Exception e) {
            throw provider.providerException("Failed to init cipher", e);
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        String modeUpperCase = mode.toUpperCase();
        if (modeUpperCase.equals("CFB8") || modeUpperCase.equals("ECB")
                || modeUpperCase.equals("CBC") || modeUpperCase.equals("CTR")
                || modeUpperCase.equals("OFB") || modeUpperCase.equals("CFB")) {
            this.mode = modeUpperCase;
        } else if (modeUpperCase.equals("CFB128")) {
            this.mode = "CFB";
        } else {
            throw new NoSuchAlgorithmException("Cipher mode: " + mode + " not found");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (padding.equalsIgnoreCase("NoPadding")) {
            this.padding = Padding.NoPadding;
        } else if (padding.equalsIgnoreCase("PKCS5Padding")) {
            this.padding = Padding.PKCS5Padding;
        } else {
            throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkCipherInitialized();

        try {
            byte[] output = null;
            int outputLen = -1;
            if (use_z_fast_command) {
                output = new byte[getOutputSizeForZ(inputLen)];
                outputLen = engineUpdate(input, inputOffset, inputLen, output, 0);
            } else {
                output = new byte[engineGetOutputSize(inputLen)];
                outputLen = symmetricCipher.update(input, inputOffset, inputLen, output, 0);
            }
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
            if (use_z_fast_command) {
                //extraChecks_update(input, inputOffset, inputLen, output, outputOffset)
                if (input == null || inputLen == 0)
                    return 0;

                // figure out how much can be sent to crypto function
                int len = buffered + inputLen;
                if (padding == Padding.PKCS5Padding && !encrypting) {
                    // do not include the padding bytes when decrypting
                    len -= engineGetBlockSize();
                }

                // do not count the trailing bytes which do not make up a unit
                len = (len > 0 ? (len - (len % 16)) : 0);

                // check output buffer capacity
                if ((output == null) || ((output.length - outputOffset) < len)) {
                    throw new ShortBufferException(
                            "Output buffer must be " + "(at least) " + len + " bytes long");
                }

                if (len != 0) {
                    // there is some work to do

                    int inputConsumed = len - buffered;
                    int bufferedConsumed = buffered;

                    if (inputConsumed < 0) {
                        // input only contains (potential) (part of) padding block, so make room for it in the buffer
                        inputConsumed = 0;
                        bufferedConsumed = len;
                    }

                    len = 0;
                    // Encrypt the buffered data first, if needed. Be careful to not process last block (which
                    // could have the padding data. Only doFinal works on last block
                    if (bufferedConsumed > 0) {
                        if (inputConsumed > 0) {
                            // Make sure the data length in buffer is multiple of unitBytes
                            // add part of a unit from data from input
                            int remainToUnit = inputConsumed % 16;
                            System.arraycopy(input, inputOffset, buffer, bufferedConsumed,
                                    remainToUnit);

                            bufferedConsumed += remainToUnit;
                            buffered += remainToUnit;
                            inputConsumed -= remainToUnit;
                            inputLen -= remainToUnit;
                            inputOffset += remainToUnit;
                        }

                        len += symmetricCipher.z_update(buffer, 0, bufferedConsumed, output,
                                outputOffset);

                        outputOffset += bufferedConsumed;
                        buffered -= bufferedConsumed;

                        if (buffered > 0) {
                            // this part of buffer could still be the padding data
                            System.arraycopy(buffer, bufferedConsumed, buffer, 0, buffered);
                        }
                    }

                    // Now process bulk of data
                    if (inputConsumed > 0) {
                        len += symmetricCipher.z_update(input, inputOffset, inputConsumed, output,
                                outputOffset);

                        inputLen -= inputConsumed;
                        inputOffset += inputConsumed;
                        outputOffset += inputConsumed;
                    }
                }
                // left over again
                if (inputLen > 0)
                    System.arraycopy(input, inputOffset, buffer, buffered, inputLen);

                buffered += inputLen;

                return len;
                // return extraChecks_update(input, inputOffset, inputLen, output, outputOffset);
            } else {
                return symmetricCipher.update(input, inputOffset, inputLen, output, outputOffset);
            }
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (Exception e) {
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

    /**
     * Gets the expected output size from the encryption of a specific input data. Function used only on Z14 machines.
     * @param inputLen
     * @return
     */
    private int getOutputSizeForZ(int inputLen) {
        int totalLen = Math.addExact(buffered, inputLen);
        if (padding == Padding.NoPadding || !encrypting)
            return totalLen;
        return Math.addExact(totalLen, 16 - (totalLen % 16));
    }

    /**
     * Helper function used only on Z14 machines.
     * @param in
     * @param off
     * @param len
     * @throws ShortBufferException
     */
    private void padWithLen(byte[] in, int off, int len) throws ShortBufferException {
        if (in == null)
            return;

        int idx = Math.addExact(off, len);
        if (idx > in.length)
            throw new ShortBufferException("Buffer too small to hold padding");

        byte paddingOctet = (byte) (len & 0xff);
        Arrays.fill(in, off, idx, paddingOctet);
    }

    /**
     * Helper function used only on Z14 machines.
     * @param in
     * @param off
     * @param len
     * @return
     */
    private int unpad(byte[] in, int off, int len) {
        if ((in == null) || (len == 0)) { // this can happen if input is really a padded buffer
            return 0;
        }
        int idx = Math.addExact(off, len);
        byte lastByte = in[idx - 1];
        int padValue = (int) lastByte & 0x0ff;
        if ((padValue < 0x01) || (padValue > 16)) {
            return -1;
        }

        int start = idx - padValue;
        if (start < off) {
            return -1;
        }

        for (int i = start; i < idx; i++) {
            if (in[i] != lastByte) {
                return -1;
            }
        }
        return start;
    }
}
