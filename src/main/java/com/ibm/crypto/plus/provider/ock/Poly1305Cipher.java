/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.Poly1305Constants;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

public final class Poly1305Cipher implements Poly1305Constants {

    private OCKContext ockContext;
    private long ockCipherId;
    private boolean isInitialized = false;
    private boolean encrypting = true;
    private Padding padding = null;
    private int bufferedCount = 0;
    private int blockSize = 0;
    private int keyLength = 0;
    private int ivLength = 0;
    private boolean needsReinit = false;
    private byte[] reinitKey = null;
    private byte[] reinitIV = null;
    private ByteArrayOutputDelay byteArrayOutputDelay = null;

    private final static String badIdMsg = "Cipher Identifier is not valid";

    public static Poly1305Cipher getInstance(OCKContext ockContext, String cipherName,
            Padding padding) throws OCKException {

        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (cipherName == null || cipherName.isEmpty()) {
            throw new IllegalArgumentException("cipherName is null/empty");
        }

        if (padding == null) {
            throw new IllegalArgumentException("padding is null");
        }

        return new Poly1305Cipher(ockContext, cipherName, padding);
    }

    private Poly1305Cipher(OCKContext ockContext, String cipherName, Padding padding)
            throws OCKException {
        this.ockContext = ockContext;
        this.ockCipherId = NativeInterface.POLY1305CIPHER_create(ockContext.getId(), cipherName);
        this.padding = padding;
    }

    public synchronized void initCipherEncrypt(byte[] key, byte[] iv) throws OCKException {
        initCipher(true, key, iv);
    }

    public synchronized void initCipherDecrypt(byte[] key, byte[] iv) throws OCKException {
        initCipher(false, key, iv);
        byteArrayOutputDelay = new ByteArrayOutputDelay(Poly1305_TAG_SIZE);
    }

    private void initCipher(boolean isEncrypt, byte[] key, byte[] iv) throws OCKException {
        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }

        if (key.length < getKeyLength()) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        if ((iv != null) && (iv.length < getIVLength())) {
            throw new IllegalArgumentException("IV is the wrong size");
        }

        if (ockCipherId == 0L) {
            throw new OCKException(badIdMsg);
        }
        NativeInterface.POLY1305CIPHER_init(ockContext.getId(), ockCipherId, isEncrypt ? 1 : 0, key,
                iv);
        NativeInterface.POLY1305CIPHER_setPadding(ockContext.getId(), ockCipherId, padding.getId());

        this.encrypting = isEncrypt ? true : false;
        this.bufferedCount = 0;
        this.needsReinit = false;
        if (key != reinitKey) {
            if (reinitKey != null) {
                Arrays.fill(reinitKey, (byte) 0x00);
            }
            this.reinitKey = key.clone();
        }
        if (iv != reinitIV) {
            this.reinitIV = (iv == null) ? null : iv.clone();
        }
        this.isInitialized = true;
    }

    public synchronized int getOutputSize(int inputLen, boolean encrypting, int tLen) {

        if (inputLen < 0) {
            return 0;
        }

        int totalLen = this.bufferedCount + inputLen;

        if (encrypting) {
            // If encrypting, will need at most buffered size + input size + tag size...
            return totalLen + tLen;
        } else {
            // If decrypting, will need at most buffered size + input size - tag size...
            return (totalLen < tLen) ? 0 : (totalLen - tLen);
        }
    }

    public synchronized int getBlockSize() throws OCKException {
        if (blockSize == 0) {
            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            blockSize = NativeInterface.POLY1305CIPHER_getBlockSize(ockContext.getId(),
                    ockCipherId);
        }

        return blockSize;
    }

    public synchronized int getKeyLength() throws OCKException {
        if (keyLength == 0) {
            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            keyLength = NativeInterface.POLY1305CIPHER_getKeyLength(ockContext.getId(),
                    ockCipherId);
        }

        return keyLength;
    }

    public synchronized int getIVLength() throws OCKException {
        if (ivLength == 0) {
            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            ivLength = NativeInterface.POLY1305CIPHER_getIVLength(ockContext.getId(), ockCipherId);
        }

        return ivLength;
    }

    public synchronized int update(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws IllegalStateException, ShortBufferException, OCKException {

        int outLen = 0;

        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (needsReinit) {
            initCipher(this.encrypting, this.reinitKey, this.reinitIV);
            needsReinit = false;
        }

        if (inputLen == 0) {
            return outLen;
        }

        if (input == null || inputLen < 0 || inputOffset < 0
                || (inputOffset + inputLen) > input.length) {
            throw new IllegalArgumentException("Input range is invalid");
        }

        if ((output != null) && ((outputOffset < 0) || (outputOffset > output.length))) {
            throw new IllegalArgumentException("Output range is invalid");
        }

        // For update output size = input size...
        int len = inputLen;
        if (!encrypting) {
            len -= byteArrayOutputDelay.getByteDelay();
        }
        if ((output != null) && (output.length != 0) && ((output.length - outputOffset) < len)) {
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        // Check if any part of the potential output overlaps the input area.  If so, then make a copy of a the input area
        // to work with so that the method is copy-safe.  A copy will be made if the input and output point to the same
        // array and if one of the following conditions is fulfilled:
        //
        //    1. If inputOffset == outputOffset
        //    2. If (inputOffset < outputOffset) and (outputOffset < (inputOffset + inputLen))
        //    3. If (inputOffset > outputOffset) and (inputOffset < (outputOffset + engineGetOutputSize(inputLen)))
        //

        byte[] copyOfInput = null;
        if (input == output) {
            if ((inputOffset == outputOffset)
                    || ((inputOffset < outputOffset) && (outputOffset < (inputOffset = inputLen)))
                    || ((inputOffset > outputOffset) && (inputOffset < (outputOffset + len)))) {
                copyOfInput = new byte[inputLen];
                System.arraycopy(input, inputOffset, copyOfInput, 0, inputLen);
                input = copyOfInput;
                inputOffset = 0;
            }
        }

        try {

            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            if (encrypting) {
                outLen = NativeInterface.POLY1305CIPHER_encryptUpdate(ockContext.getId(),
                        ockCipherId, input, inputOffset, inputLen, output, outputOffset);
            } else {
                if (null != output) { //NOT updateAAD call
                    byte[] delayedInput = getDelayedInput(input, inputOffset, inputLen);
                    outLen = NativeInterface.POLY1305CIPHER_decryptUpdate(ockContext.getId(),
                            ockCipherId, delayedInput, 0, delayedInput.length, output,
                            outputOffset);
                } else {
                    outLen = NativeInterface.POLY1305CIPHER_decryptUpdate(ockContext.getId(),
                            ockCipherId, input, inputOffset, inputLen, output, outputOffset);
                }
            }
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }

        this.bufferedCount += inputLen - outLen;

        return outLen;
    }

    public synchronized int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, OCKException {

        byte[] tag = new byte[Poly1305_TAG_SIZE];
        byte[] cipherText = null;
        int cipherTextLen = 0;
        int outLen = 0;

        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (needsReinit) {
            initCipher(this.encrypting, this.reinitKey, this.reinitIV);
            needsReinit = false;
        }

        if (inputLen != 0) {
            if (input == null || inputLen < 0 || inputOffset < 0
                    || (inputOffset + inputLen) > input.length) {
                throw new IllegalArgumentException("Input range is invalid");
            }
        }

        if (!this.encrypting) {
            input = getFinalCipherTextInput(input, inputOffset, inputLen);
            inputOffset = 0;
            inputLen = input.length;

            // Input must at least contain the cipher tag...
            if (tag == null && ((input == null) || (inputLen < Poly1305_TAG_SIZE))) {
                throw new IllegalArgumentException("Missing tag on decrypt final");
            } else {
                // Input contains cipher text, as well...
                if (inputLen > Poly1305_TAG_SIZE) {
                    cipherTextLen = inputLen - Poly1305_TAG_SIZE;
                    cipherText = new byte[cipherTextLen];
                }
            }
        }

        if (encrypting) {
            if ((output == null) || (outputOffset < 0) || (outputOffset > output.length)) {
                throw new IllegalArgumentException("Output range is invalid");
            }
        }

        // If we are decrypting or if we are encrypting with NoPadding, then
        // total input must be a multiple of the block size.
        //
        if (!this.encrypting || (this.padding.isPadding(Padding.PADDING_NONE))) {
            if ((inputLen + bufferedCount) % getBlockSize() != 0) {
                throw new IllegalBlockSizeException(
                        "Message must be a multiple of the block size without padding");
            }
        }

        int len = getOutputSize(inputLen, this.encrypting, Poly1305_TAG_SIZE);
        if (!encrypting) {
            len = len - Poly1305_TAG_SIZE;
        }
        if ((output.length - outputOffset) < len) {
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        // Check if any part of the potential output overlaps the input area.  If so, then make a copy of a the input area
        // to work with so that the method is copy-safe.  A copy will be made if the input and output point to the same
        // array and if one of the following conditions is fulfilled:
        //
        //    1. If inputOffset == outputOffset
        //    2. If (inputOffset < outputOffset) and (outputOffset < (inputOffset + inputLen))
        //    3. If (inputOffset > outputOffset) and (inputOffset < (outputOffset + engineGetOutputSize(inputLen)))
        //

        byte[] copyOfInput = null;
        if (input == output) {
            if ((inputOffset == outputOffset)
                    || ((inputOffset < outputOffset) && (outputOffset < (inputOffset = inputLen)))
                    || ((inputOffset > outputOffset) && (inputOffset < (outputOffset + len)))) {
                copyOfInput = new byte[inputLen];
                System.arraycopy(input, inputOffset, copyOfInput, 0, inputLen);
                input = copyOfInput;
                inputOffset = 0;
            }
        }

        try {
            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            if (encrypting) {
                // Cipher text length is same as plain text length...
                outLen = NativeInterface.POLY1305CIPHER_encryptFinal(ockContext.getId(),
                        ockCipherId, input, inputOffset, inputLen, output, outputOffset, tag);
                // Append tag to output...
                System.arraycopy(tag, 0, output, outLen + outputOffset, Poly1305_TAG_SIZE);
                // Output length is cipher text length plus tag length...
                outLen += Poly1305_TAG_SIZE;
            } else {
                // Parse tag from input...
                System.arraycopy(input, (inputLen - Poly1305_TAG_SIZE), tag, 0, Poly1305_TAG_SIZE);
                // Parse cipher text from input...
                if (cipherText != null) {
                    System.arraycopy(input, 0, cipherText, 0, cipherTextLen);
                }
                // Output length is equal to total cipher text length including buffered text...
                outLen = NativeInterface.POLY1305CIPHER_decryptFinal(ockContext.getId(),
                        ockCipherId, cipherText, inputOffset, cipherTextLen, output, outputOffset,
                        tag);
            }
        } catch (OCKException e) {
            if (e.getCode() == OCKException.GKR_DECRYPT_FINAL_BAD_PADDING_ERROR) {
                throw new BadPaddingException("Unexpected padding");
            } else {
                throw e;
            }
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }

        // All buffered data has been processed. Reset buffered count for future operations
        this.bufferedCount = 0;

        // Need to reset the object such that it can be re-used.
        this.needsReinit = true;
        return outLen;
    }

    @Override
    protected synchronized void finalize() throws Throwable {
        try {
            if (ockCipherId != 0) {
                NativeInterface.POLY1305CIPHER_delete(ockContext.getId(), ockCipherId);
                ockCipherId = 0;
            }
        } finally {
            if (reinitKey != null) {
                Arrays.fill(reinitKey, (byte) 0x00);
                reinitKey = null;
            }

            super.finalize();
        }
    }

    /* At some point we may enhance this function to do other validations */
    private static boolean validId(long id) {
        return (id != 0L);
    }

    private byte[] getDelayedInput(byte[] input, int inputOffset, int inputLen) {
        return byteArrayOutputDelay.write(input, inputOffset, inputLen);
    }

    private byte[] getFinalCipherTextInput(byte[] input, int inputOffset, int inputLen) {
        byte[] delayedInput = byteArrayOutputDelay.flush();

        ByteArrayOutputStream baos = new ByteArrayOutputStream(delayedInput.length + inputLen);
        baos.write(delayedInput, 0, delayedInput.length);
        if (null != input) {
            baos.write(input, inputOffset, inputLen);
        }
        return baos.toByteArray();
    }
}
