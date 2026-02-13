/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

public final class SymmetricCipher {

    private OpenJCEPlusProvider provider;
    private OCKContext ockContext;
    private final long ockCipherId;
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
    private byte[] reinitIVAndKey = null;
    // CBC Upgrade variables
    private int mode; // Mode used by z_kmc
    private FastJNIBuffer parameters; // Fast way to pass all parameters in z_kmc call
    private static final int PARAM_CAP = 1024 * 6; // Capacity of the FastJNIBUffer
    private long inputPointer; // Pointer to memory that has the input to be encrypted by z_kmc
    private long outputPointer; // Pointer to memory that has the output to the encrypted text by z_kmc
    private long outputOffset; // Offset, in the buffer, to where the output is stored, used to retrieve output after z_kmc call
    private long paramPointer; // Pointer to memory that has the parameters/state keeping used by z_kmc
    private static long hardwareFunctionPtr = 0;
    private final boolean use_z_fast_command;
    private static final ConcurrentHashMap<OCKContext, Boolean> hardwareEnabled = new ConcurrentHashMap<>(); // Caching for hardwareFunctionPtr
    private static final String badIdMsg = "Cipher Identifier is not valid";
    /* private final static String debPrefix = "SymCipher"; Adding Debug causes test cases to fail */
    int paramOffset;
    FastJNIBuffer parametersBuffer = null;
    // GSKit code adds 16 to the input buffer length for every Update  and provide a 
    // 16  byte buffer for the Final which has no input data.
    private final int OCK_ENCRYPTION_RESIDUE = 16;
    //final String debPrefix = "SymmetricCipher";


    public static SymmetricCipher getInstanceChaCha20(OCKContext ockContext, Padding padding, OpenJCEPlusProvider provider)
            throws OCKException {
        String algName = "chacha20";
        return getInstance(ockContext, algName, padding, provider);
    }

    public static SymmetricCipher getInstanceChaCha20Poly1305(OCKContext ockContext,
            Padding padding, OpenJCEPlusProvider provider) throws OCKException {
        String algName = "chacha20-poly1305";
        return getInstance(ockContext, algName, padding, provider);
    }

    public static SymmetricCipher getInstanceAES(OCKContext ockContext, String mode,
            Padding padding, int numKeyBytes, OpenJCEPlusProvider provider) throws OCKException {
        String algName = "AES-" + Integer.toString(numKeyBytes * 8) + "-" + mode.toUpperCase();
        return getInstance(ockContext, algName, padding, provider);
    }

    public static SymmetricCipher getInstanceDESede(OCKContext ockContext, String mode,
            Padding padding, OpenJCEPlusProvider provider) throws OCKException {
        String modeUpperCase = mode.toUpperCase();
        String algName = modeUpperCase.equals("ECB") ? "DES-EDE3" : "DES-EDE3-" + modeUpperCase;
        return getInstance(ockContext, algName, padding, provider);
    }

    public static SymmetricCipher getInstanceRC2(OCKContext ockContext, String mode,
            Padding padding, int keysize, OpenJCEPlusProvider provider) throws OCKException {
        String modeUpperCase = mode.toUpperCase();
        String algName;
        if (keysize == 16)
            algName = modeUpperCase.equals("ECB") ? "RC2" : "RC2-" + modeUpperCase;
        else 
            algName = modeUpperCase.equals("ECB") ? "RC2" : "RC2-40-" + modeUpperCase;
        return getInstance(ockContext, algName, padding, provider);
    }

    public static SymmetricCipher getInstanceRC4(OCKContext ockContext, int keysize,
            OpenJCEPlusProvider provider) throws OCKException {
        String algName = keysize == 16 ? "RC4" : "RC4-40"; 
        return getInstance(ockContext, algName, Padding.NoPadding, provider);
    }

    private static SymmetricCipher getInstance(OCKContext ockContext, String cipherName,
            Padding padding, OpenJCEPlusProvider provider) throws OCKException {
        //final String methodName = "getInstance";
        if (ockContext == null) {
            throw new IllegalArgumentException("context is null");
        }

        if (cipherName == null || cipherName.isEmpty()) {
            throw new IllegalArgumentException("cipherName is null/empty");
        }

        if (padding == null) {
            throw new IllegalArgumentException("padding is null");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }
        //OCKDebug.Msg(debPrefix, methodName, "cipherName :" + cipherName);

        return new SymmetricCipher(ockContext, cipherName, padding, provider);
    }

    static void throwOCKException(int errorCode) throws BadPaddingException, OCKException {
        switch (errorCode) {
            case -1:
                throw new OCKException("ICC_EVP_EncryptUpdate failed!");
            case -2:
                throw new OCKException("ICC_EVP_EncryptFinal failed!");
            case -3:
                throw new OCKException("ICC_EVP_DecryptUpdate failed!");
            case -4:
                throw new OCKException("ICC_EVP_DecryptFinal failed!");
            case -5:
                throw new BadPaddingException("Unexpected padding");
            default:
                throw new OCKException("Unknow Error Code");
        }
    }

    private SymmetricCipher(OCKContext ockContext, String cipherName, Padding padding, OpenJCEPlusProvider provider)
            throws OCKException {
        // Check whether used algorithm is CBC and whether hardware supports
        this.provider = provider;
        boolean isHardwareSupport = false;
        if (hardwareEnabled.containsKey(ockContext))
            isHardwareSupport = hardwareEnabled.get(ockContext);
        else {
            hardwareFunctionPtr = checkHardwareSupport(ockContext.getId());
            isHardwareSupport = (hardwareFunctionPtr == 1) ? true : false;
            hardwareEnabled.put(ockContext, isHardwareSupport);
        }
        use_z_fast_command = "AES".equals(cipherName.substring(0, 3))
                && "CBC".equals(cipherName.substring(cipherName.length() - 3)) && isHardwareSupport;

        this.ockContext = ockContext;
        this.padding = padding;
        if (!use_z_fast_command) {
            this.ockCipherId = NativeInterface.CIPHER_create(ockContext.getId(), cipherName);
        } else {
            this.ockCipherId = 0L;
        }

        this.provider.registerCleanable(this, cleanOCKResources(use_z_fast_command, ockCipherId, reinitKey, ockContext));
    }

    public synchronized void initCipherEncrypt(byte[] key, byte[] iv) throws OCKException {
        initCipher(true, key, iv);
    }

    public synchronized void initCipherDecrypt(byte[] key, byte[] iv) throws OCKException {
        initCipher(false, key, iv);
    }

    private void initCipher(boolean isEncrypt, byte[] key, byte[] iv) throws OCKException {
        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }
        if ((iv != null) && (iv.length < getIVLength())) {
            throw new IllegalArgumentException("IV is the wrong size");
        }

        if (!use_z_fast_command) {
            if (key.length < getKeyLength()) {
                throw new IllegalArgumentException("key is the wrong size");
            }
            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            NativeInterface.CIPHER_init(ockContext.getId(), ockCipherId, isEncrypt ? 1 : 0,
                    padding.getId(), key, iv);
        }

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

        // Create cached version
        if (reinitIV != null && reinitKey != null) {
            reinitIVAndKey = new byte[reinitIV.length + reinitKey.length];
            System.arraycopy(reinitIV, 0, reinitIVAndKey, 0, reinitIV.length);
            System.arraycopy(reinitKey, 0, reinitIVAndKey, reinitIV.length, reinitKey.length);
        }

        if (use_z_fast_command) {
            if (parametersBuffer == null) {
                parametersBuffer = FastJNIBuffer.create(PARAM_CAP);
            }
            // Calculating pointers/offsets
            // parameters = SymmetricCipher.parametersBuffer.get();
            inputPointer = parametersBuffer.pointer();
            paramOffset = PARAM_CAP - iv.length - key.length;
            paramPointer = parametersBuffer.pointer() + paramOffset;
            outputOffset = paramOffset / 2; // Max output = Max input = (Buffer Capacity - (Key Length + IV Length)) / 2
            outputPointer = parametersBuffer.pointer() + outputOffset;

            // Adding iv and key to params buffer
            parametersBuffer.put(paramOffset, iv, 0, iv.length);
            parametersBuffer.put(paramOffset + iv.length, key, 0, key.length);

            // Determine mode
            mode = (isEncrypt) ? 0 : 128;
            blockSize = 16;
            switch (key.length) {
                case 8:
                    mode += 1;
                    break;
                case 16:
                    if (blockSize == 8)
                        mode += 2;
                    else if (blockSize == 16)
                        mode += 18;
                    break;
                case 24:
                    if (blockSize == 8)
                        mode += 3;
                    else if (blockSize == 16)
                        mode += 19;
                    break;
                case 32:
                    mode += 20;
                    break;
            }
        }
    }

    // public synchronized void clean() throws OCKException {
    // NativeInterface.CIPHER_clean(ockContext.getId(), ockCipherId);
    // this.bufferedCount = 0;
    // }
    public int getOutputSize(int inputLen) throws OCKException {
        return getOutputSize(inputLen, true);
    }

    public synchronized int getOutputSize(int inputLen, boolean isFinal) throws OCKException {
        //final String methodName = "getOutputSize";
        if (inputLen < 0) {
            return 0;
        }
        //OCKDebug.Msg (debPrefix, methodName, "inputLen=" + inputLen + " isFinal=" + isFinal + "encrypting=" + encrypting );
        int totalLen = this.bufferedCount + inputLen;
        int blockSize = getBlockSize();
        //OCKDebug.Msg (debPrefix, methodName, "totalLen=" + totalLen + " blockSize=" + blockSize);
        if (padding.isPadding(Padding.PADDING_NONE)) {
            return totalLen;
        }

        if (!encrypting) {
            return totalLen;
        }
        int retLen = 0;
        int remainderBytes = totalLen % blockSize;
        if (isFinal) {
            retLen = totalLen + (blockSize - remainderBytes);
        } else {
            retLen = totalLen;
        }

        //OCKDebug.Msg (debPrefix, methodName, "retLen = " + retLen);
        return retLen;
    }

    /**
     * OCKC always oversizes the buffer by 16 bytes (i.e. 128 bits).
     *
     * This buffer is larger than what end user application will provide typically as a 
     * buffer. This method calculates the amount of space that is needed by OCKC in order
     * to perform its operations.
     *
     * @param inputLen the length of the input buffer used to calulate the necessary
     * buffer size needed for the OCKC library.
     * @return the necessary buffer size needed by OCK.
     */
    private synchronized int getOutputSizeForOCK(int inputLen) throws OCKException {
        //final String methodName = "getOutputSize";
        if (inputLen < 0) {
            throw new OCKException("Input length not expected to be < 0");
        }
        //OCKDebug.Msg (debPrefix, methodName, "inputLen=" + inputLen + " isFinal=" + isFinal + "encrypting=" + encrypting );
        int totalLen = this.bufferedCount + inputLen;
        int blockSize = getBlockSize();
        //OCKDebug.Msg (debPrefix, methodName, "totalLen=" + totalLen + " blockSize=" + blockSize);

        int remainderBytes = totalLen % blockSize;

        int retLen = totalLen + (blockSize - remainderBytes) + OCK_ENCRYPTION_RESIDUE;

        // OCKDebug.Msg (debPrefix, methodName, "retLen = " + retLen);
        return retLen;
    }

    public synchronized int getBlockSize() throws OCKException {
        if (blockSize == 0) {
            if (!use_z_fast_command) {
                if (ockCipherId == 0L)
                    throw new OCKException(badIdMsg);
                blockSize = NativeInterface.CIPHER_getBlockSize(ockContext.getId(), ockCipherId);
            } else {
                blockSize = 16;
            }
        }
        return blockSize;
    }

    public synchronized int getKeyLength() throws OCKException {
        if (keyLength == 0) {
            if (!use_z_fast_command) {
                if (ockCipherId == 0L) {
                    throw new OCKException(badIdMsg);
                }
                keyLength = NativeInterface.CIPHER_getKeyLength(ockContext.getId(), ockCipherId);
            } else {
                keyLength = 16;
            }
        }
        return keyLength;
    }

    public synchronized int getIVLength() throws OCKException {
        if (ivLength == 0 && !use_z_fast_command) {
            if (ockCipherId == 0L)
                throw new OCKException(badIdMsg);
            ivLength = NativeInterface.CIPHER_getIVLength(ockContext.getId(), ockCipherId);
        }
        return ivLength;
    }

    // public synchronized int getOID() {
    // return NativeInterface.CIPHER_getOID(ockContext.getId(), ockCipherId);
    // }

    public synchronized int update(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws IllegalStateException, ShortBufferException, BadPaddingException, OCKException {
        //final String methodName = "update";
        int outLen = 0;
        //        OCKDebug.Msg (debPrefix, methodName, "input.length=" + input.length +
        //                " inputoffset=" + inputOffset + " inputLen=" + inputLen +
        //                " output.length=" + output.length  + " outputOffset="  + outputOffset);

        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (inputLen == 0) {
            return outLen;
        }

        if (input == null || inputLen < 0 || inputOffset < 0
                || (inputOffset + inputLen) > input.length) {
            throw new IllegalArgumentException("Input range is invalid");
        }

        if (output == null || outputOffset < 0 || (outputOffset > output.length)) {
            throw new IllegalArgumentException("Output range is invalid");
        }

        int len = getOutputSize(inputLen, false);
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
                    || ((inputOffset < outputOffset) && (outputOffset < (inputOffset + inputLen)))
                    || ((inputOffset > outputOffset) && (inputOffset < (outputOffset + len)))) {
                copyOfInput = new byte[inputLen];
                System.arraycopy(input, inputOffset, copyOfInput, 0, inputLen);
                input = copyOfInput;
                inputOffset = 0;
            }
        }

        byte[] tmpBuf = new byte[getOutputSizeForOCK(inputLen)];
        try {
            //OCKDebug.Msg (debPrefix, methodName, "ockCipherId :" + ockCipherId + " inputOffset :" + inputOffset + " inputLen :" + inputLen + "encrypting :" + encrypting);
            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            if (encrypting) {
                outLen = NativeInterface.CIPHER_encryptUpdate(ockContext.getId(), ockCipherId,
                        input, inputOffset, inputLen, tmpBuf, 0, needsReinit);
            } else {
                outLen = NativeInterface.CIPHER_decryptUpdate(ockContext.getId(), ockCipherId,
                        input, inputOffset, inputLen, tmpBuf, 0, needsReinit);
            }
            if (outLen < 0) {
                throwOCKException(outLen);
            }
            if (outLen > (output.length - outputOffset)) {
                throw new ShortBufferException(
                        "Output buffer must be (at least) " + outLen + " bytes long");
            }

            System.arraycopy(tmpBuf, 0, output, outputOffset, outLen);
            needsReinit = false;
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }

        this.bufferedCount += inputLen - outLen;
        //OCKDebug.Msg(debPrefix, methodName, "outLen=" + outLen);
        return outLen;
    }

    public synchronized int z_update(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws IllegalStateException, ShortBufferException, OCKException {
        int outLen = 0;

        if (needsReinit) {
            // Resetting iv and key to params buffer
            if (reinitIVAndKey != null)
                parametersBuffer.put(paramOffset, reinitIVAndKey, 0, reinitIVAndKey.length);
            else {
                parametersBuffer.put(paramOffset, this.reinitIV, 0, reinitIV.length);
                parametersBuffer.put(paramOffset + reinitIV.length, this.reinitKey, 0,
                        reinitKey.length);
            }
            needsReinit = false;
        }

        outLen = NativeInterface.z_kmc_native(input, inputOffset, output, outputOffset,
                paramPointer, inputLen, mode);
        return outLen;
    }

    public synchronized int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, OCKException {
        //final String methodName = "doFinal";

        int outLen = 0;

        if (!this.isInitialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        if (inputLen != 0) {
            if (input == null || inputLen < 0 || inputOffset < 0
                    || (inputOffset + inputLen) > input.length) {
                throw new IllegalArgumentException("Input range is invalid");
            }
        }

        if ((output == null) || (outputOffset < 0) || (outputOffset > output.length)) {
            throw new IllegalArgumentException("Output range is invalid");
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

        int len = getOutputSize(inputLen);

        //Determine if there is anything to do. If the input i nothing and there is nothing to process
        //The skip doing anything and just return with a length of zero and reset stuff for reuse.
        if (len == 0) {

            // All buffered data has been processed. Reset buffered count for future
            // operations
            //
            this.bufferedCount = 0;

            // Need to reset the object such that it can be re-used.
            //
            this.needsReinit = true;
            //OCKDebug.Msg (debPrefix, methodName, "outLen=" + outLen);
            return len;
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
                    || ((inputOffset < outputOffset) && (outputOffset < (inputOffset + inputLen)))
                    || ((inputOffset > outputOffset) && (inputOffset < (outputOffset + len)))) {
                copyOfInput = new byte[inputLen];
                System.arraycopy(input, inputOffset, copyOfInput, 0, inputLen);
                input = copyOfInput;
                inputOffset = 0;
            }
        }
        // Customer provided buffer may be smaller than what OCK requires.
        byte[] tmpBuf = new byte[getOutputSizeForOCK(inputLen)];

        try {
            //OCKDebug.Msg (debPrefix, methodName, "ockCipherId :" + ockCipherId + " inputOffset :" + inputOffset + " inputLen :" + inputLen + "encrypting :" + encrypting);
            //OCKDebug.Msg(debPrefix, methodName, "input bytes :", input);
            if (ockCipherId == 0L) {
                throw new OCKException(badIdMsg);
            }
            if (encrypting) {
                outLen = NativeInterface.CIPHER_encryptFinal(ockContext.getId(), ockCipherId, input,
                        inputOffset, inputLen, tmpBuf, 0, needsReinit);
            } else {
                outLen = NativeInterface.CIPHER_decryptFinal(ockContext.getId(), ockCipherId, input,
                        inputOffset, inputLen, tmpBuf, 0, needsReinit);
            }
            if (outLen < 0) {
                throwOCKException(outLen);
            }
            if (outLen > (output.length - outputOffset)) {
                throw new ShortBufferException(
                        "Output buffer must be (at least) " + outLen + " bytes long");
            }
            System.arraycopy(tmpBuf, 0, output, outputOffset, outLen);
        } catch (OCKException e) {
            throw e;
        } finally {
            if ((copyOfInput != null) && encrypting) {
                Arrays.fill(copyOfInput, (byte) 0x00);
            }
        }

        // All buffered data has been processed. Reset buffered count for future
        // operations
        //
        this.bufferedCount = 0;

        // Need to reset the object such that it can be re-used.
        //
        this.needsReinit = true;
        //OCKDebug.Msg (debPrefix, methodName, "outLen=" + outLen);
        return outLen;
    }

    public synchronized int z_doFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, OCKException {

        int outLen = 0;

        if (needsReinit) {
            // Resetting iv and key to params buffer
            if (reinitIVAndKey != null)
                parametersBuffer.put(paramOffset, reinitIVAndKey, 0, reinitIVAndKey.length);
            else {
                parametersBuffer.put(paramOffset, this.reinitIV, 0, reinitIV.length);
                parametersBuffer.put(paramOffset + reinitIV.length, this.reinitKey, 0,
                        reinitKey.length);
            }
            needsReinit = false;
        }

        if (inputLen != 0 && (input == null || inputLen < 0 || inputOffset < 0
                || (inputOffset + inputLen) > input.length))
            throw new IllegalArgumentException("Input range is invalid");

        outLen = NativeInterface.z_kmc_native(input, inputOffset, output, outputOffset,
                paramPointer, inputLen, mode);

        // Need to reset the object such that it can be re-used.
        this.needsReinit = true;
        //OCKDebug.Msg (debPrefix, methodName, "outLen=" + outLen);
        return outLen;
    }

    /* At some point we may enhance this function to do other validations */
    protected static boolean validId(long id) {
        //final String methodName = "validId";
        //OCKDebug.Msg (debPrefix, methodName, "id :" + id);
        return (id != 0L);
    }

    private static long checkHardwareSupport(long ockId) {
        return NativeInterface.checkHardwareSupport(ockId);
    }

    public boolean getHardwareSupportStatus() {
        return use_z_fast_command;
    }

    public void resetParams() {
        this.needsReinit = true;
    }

    public static String hexToAscii(byte[] b) {
        char[] hexDigits = "0123456789abcdef".toCharArray();
        if (b == null) {
            return "(null)";
        }
        StringBuffer sb = new StringBuffer(b.length * 3);
        for (int i = 0; i < b.length; i++) {
            int k = b[i] & 0xff;
            if (i != 0) {
                sb.append(':');
            }
            sb.append(hexDigits[k >>> 4]);
            sb.append(hexDigits[k & 0xf]);
        }
        return sb.toString();
    }

    public static byte[] asciiToHex(String s) {
        try {
            int n = s.length();
            ByteArrayOutputStream out = null;
            if (s.contains(":")) {
                out = new ByteArrayOutputStream(n / 3);
            } else {
                out = new ByteArrayOutputStream(n / 2);
            }

            StringReader r = new StringReader(s);
            while (true) {
                int b1 = nextNibble(r);
                if (b1 < 0) {
                    break;
                }
                int b2 = nextNibble(r);
                if (b2 < 0) {
                    break;
                }
                int b = (b1 << 4) | b2;
                out.write(b);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static int nextNibble(StringReader r) throws IOException {
        while (true) {
            int ch = r.read();
            if (ch == -1) {
                return -1;
            } else if ((ch >= '0') && (ch <= '9')) {
                return ch - '0';
            } else if ((ch >= 'a') && (ch <= 'f')) {
                return ch - 'a' + 10;
            } else if ((ch >= 'A') && (ch <= 'F')) {
                return ch - 'A' + 10;
            }
        }
    }

    private Runnable cleanOCKResources(boolean use_z_fast_command, long ockCipherId, byte[] reinitKey, OCKContext ockContext){
        return() -> {
            try {
                if (!use_z_fast_command) {
                    if (ockCipherId != 0) {
                        NativeInterface.CIPHER_delete(ockContext.getId(), ockCipherId);
                    }
                }
                if (reinitKey != null) {
                    Arrays.fill(reinitKey, (byte) 0x00);
                }
            } catch (Exception e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
