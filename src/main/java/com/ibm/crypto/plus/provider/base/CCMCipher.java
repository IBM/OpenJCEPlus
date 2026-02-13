/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

public final class CCMCipher {
    private static final boolean disableCCMAcceleration;
    private static final String DISABLE_CCM_ACCELERATION = "com.ibm.crypto.provider.DisableCCMAcceleration";
    private static final String debPrefix = "CCMCipher";
    private static long CCMHardwareFunctionPtr = -1; // Disable hardware AES/CCM for System Z

    static final int parameterBlockSize = 80;
    static final int TAADLOffset = 48;
    static final int TPCLOffset = 56;
    static final int keyOffset = 80;

    static final int CCM_MODE_128 = 18;
    static final int CCM_MODE_192 = 19;
    static final int CCM_MODE_256 = 20;
    static final int CCM_MODE_DECRYPT = 128;
    static final int CCM_AUGMENTED_MODE = 768;

    static {
        disableCCMAcceleration = Boolean.parseBoolean(
            System.getProperty(DISABLE_CCM_ACCELERATION, "false"));
    }


    // Buffer to pass CCM input to native
    private static final ThreadLocal<FastJNIBuffer> inputBuffer = new ThreadLocal<FastJNIBuffer>() {
        @Override
        protected FastJNIBuffer initialValue() {
            return FastJNIBuffer.create(FastJNIInputBufferSize);
        }
    };


    // Buffer to get CCM output from native
    private static final ThreadLocal<FastJNIBuffer> outputBuffer = new ThreadLocal<FastJNIBuffer>() {
        @Override
        protected FastJNIBuffer initialValue() {
            return FastJNIBuffer.create(FastJNIOutputBufferSize);
        }
    };


    // ByteArray buffer to pass/get errCode key, IV, AAD, tag
    private static final ThreadLocal<FastJNIBuffer> parameterBuffer = new ThreadLocal<FastJNIBuffer>() {
        @Override
        protected FastJNIBuffer initialValue() {
            return FastJNIBuffer.create(FastJNIParameterBufferSize);
        }
    };


    private static final Map<Integer, String> ErrorCodes;

    static {
        ErrorCodes = new HashMap<Integer, String>();
        ErrorCodes.put(1, "ICC_AES_CCM_CTX_new failed");
        ErrorCodes.put(2, "ICC_AES_CCM_Init failed - Error initializing in En/Decrypt");
        ErrorCodes.put(3, "ICC_AES_CCM_En/DecryptUpdate failed");
        ErrorCodes.put(4, "ICC_AES_CCM_En/DecryptFinal failed");
        ErrorCodes.put(5, "NULL from GetPrimitiveArrayCritical");
        ErrorCodes.put(6, "ICC_AES_CCM_DecryptFinal failed: Tag Mismatch!\n");

        //        int tls_support_result=1;
        //        try {
        //            tls_support_result = NativeInterface.get_CCM_TLSEnabled();
        //        } catch (OCKException e) {
        //            tls_support_result = 1;
        //        }
        //Java Thread Local Storage is always enabled.
        //useJavaTLS = true; //(tls_support_result != 0);
        //OCKDebug.Msg (debPrefix,  "static", "UseJavaTLS" + useJavaTLS);
    }

    private static final int FastJNIInputBufferSize = 1024 * 2 * 2;
    private static final int FastJNIOutputBufferSize = 1024 * 2 * 2 + 16;
    private static final int FastJNIParameterBufferSize = 1024;

    // AES-CCM constants in Bytes
    private static final int AES_CCM_MIN_KEY_SIZE = 16;
    private static final int AES_CCM_MIN_IV_SIZE = 1;
    private static final byte[] emptyAAD = new byte[0];

    // it is not synchronized since there are no shared OCK data structures used in the OCK call
    // except ICC_CTX which is thread safe

    public static int doCCMFinal_Decrypt(OCKContext ockContext, byte[] key, byte[] iv, int tagLen,
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset,
            byte[] aad) throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, AEADBadTagException {

        //final String methodName="doCCMFinal_Decrypt ";
        int rc = 0;
        byte[] authenticationData;

        //OCKDebug.Msg(debPrefix, methodName,  "key :" + key);
        //OCKDebug.Msg(debPrefix, methodName,  "iv :" + iv);
        //OCKDebug.Msg(debPrefix, methodName,"input :" + input);
        //OCKDebug.Msg(debPrefix, methodName, "aad :" + aad);
        //OCKDebug.Msg(debPrefix, methodName,  "tagLen :" + tagLen + " inputOffset :" + inputOffset + "outputOffset :" + outputOffset);

        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }

        if ((iv == null)) {
            throw new IllegalArgumentException("IV is null");
        }

        if (key.length < AES_CCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        if ((iv != null) && (iv.length < AES_CCM_MIN_IV_SIZE)) {
            throw new IllegalArgumentException("IV is the wrong size");
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

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSizeLegacy(inputLen, false /*isEncrypt*/, tagLen);
        if ((output == null) || ((output.length - outputOffset) < len)) {
            //OCKDebug.Msg(debPrefix, methodName,  "throwing ShortBufferException  outputlength = " + output.length + " outputOffset=" + outputOffset + "len=" + len);
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        // Check if any part of the potential output overlaps the input area. If
        // so, then make a copy of a the input area
        // to work with so that the method is copy-safe. A copy will be made if
        // the input and output point to the same
        // array and if one of the following conditions is fulfilled:
        //
        // 1. If inputOffset == outputOffset
        // 2. If (inputOffset < outputOffset) and (outputOffset < (inputOffset +
        // inputLen))
        // 3. If (inputOffset > outputOffset) and (inputOffset < (outputOffset +
        // engineGetOutputSize(inputLen)))
        //
        //        byte[] copyOfInput = null;
        //        if (input == output) {
        //               //OCKDebug.Msg (debPrefix, methodName,  "input == output");
        //
        //                if ((inputOffset == outputOffset)
        //                    || ((inputOffset < outputOffset) && (outputOffset < (inputOffset = inputLen)))
        //                    || ((inputOffset > outputOffset) && (inputOffset < (outputOffset + len)))) {
        //                    copyOfInput = new byte[inputLen];
        //                    System.arraycopy(input, inputOffset, copyOfInput, 0, inputLen);
        //                    input = copyOfInput;
        //                    inputOffset = 0;
        //                }
        //        }

        if ((input == output) && (outputOffset - inputOffset < inputLen)) {
            // && (inputOffset - outputOffset < buffer.length)) {
            // copy 'input' out to avoid its content being
            // overwritten prematurely.
            input = Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen));
            inputOffset = 0;
        }

        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        int aadLen = authenticationData.length;

        if (CCMHardwareFunctionPtr == 0) {
            CCMHardwareFunctionPtr = NativeInterface
                    .do_CCM_checkHardwareCCMSupport(ockContext.getId());
        }

        if (iv.length + key.length + aadLen <= FastJNIParameterBufferSize && !disableCCMAcceleration
                && (inputLen <= FastJNIInputBufferSize || CCMHardwareFunctionPtr != -1)) {
            FastJNIBuffer parameters = CCMCipher.parameterBuffer.get();
            parameters.put(0, iv, 0, iv.length);
            parameters.put(iv.length, authenticationData, 0, aadLen);

            //OCKDebug.Msg (debPrefix, methodName,  "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
            //OCKDebug.Msg (debPrefix, methodName,   " inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen :" + tagLen);

            if (CCMHardwareFunctionPtr != -1) { // hardware supports fast CCM command
                rc = useHardwareCCM(false, inputLen, iv.length, key.length, aadLen, tagLen, key,
                        input, inputOffset, output, outputOffset, parameters);
            } else {
                FastJNIBuffer outputBuffer = CCMCipher.outputBuffer.get();
                FastJNIBuffer inputBuffer = CCMCipher.inputBuffer.get();
                inputBuffer.put(0, input, inputOffset, inputLen);
                parameters.put(iv.length + aadLen, key, 0, key.length);
                rc = NativeInterface.do_CCM_decryptFastJNI(ockContext.getId(), key.length,
                        iv.length, inputLen, output.length, aadLen, tagLen, parameters.pointer(),
                        inputBuffer.pointer(), outputBuffer.pointer());

                // Copy Output + Tag out of native data buffer
                outputBuffer.get(0, output, outputOffset, len);
            }

            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            }
        } else {
            //OCKDebug.Msg (debPrefix, methodName, "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
            //OCKDebug.Msg (debPrefix, methodName, " inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen :" + tagLen);

            // Create tempInput
            byte[] tempInput = new byte[inputLen];
            // Copy contents of input from inputOffset for length inputLen into tempInput
            System.arraycopy(input, inputOffset, tempInput, 0, inputLen); // inputLen should be good

            // Create tempOutput
            byte[] tempOutput = new byte[len + outputOffset]; // len from call to getOutputSizeLegacy() above

            rc = NativeInterface.do_CCM_decrypt(ockContext.getId(), iv, iv.length, key, key.length,
                    authenticationData, aadLen, tempInput, inputLen, tempOutput, tempOutput.length,
                    tagLen);

            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            } else {
                // Copy contents of tempOutput to output at outputOffset for len bytes
                // len is at least output.length + outputOffset
                System.arraycopy(tempOutput, 0, output, outputOffset, len);
            }
        }
        return len;
    }

    // it is not synchronized since there are no shared OCK data structures used in the OCK call
    // except ICC_CTX which is thread safe

    public static int doCCMFinal_Encrypt(OCKContext ockContext, byte[] key, byte[] iv, int tagLen,
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset,
            byte[] aad) throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {

        //final String methodName = "doCCMFinal_Encrypt ";
        byte[] authenticationData;
        int outputBufLen = output.length;
        int rc = 0;
        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }
        int keyLen = key.length;

        if (iv == null) {
            throw new IllegalArgumentException("IV is null");
        }

        if (keyLen < AES_CCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        int ivLen = iv.length;
        if (ivLen < AES_CCM_MIN_IV_SIZE) {
            throw new IllegalArgumentException("IV is the wrong size");
        }

        if (inputLen != 0) {
            if (input == null || inputLen < 0 || inputOffset < 0
                    || (inputOffset + inputLen) > input.length) {
                throw new IllegalArgumentException("Input range is invalid");
            }
        }

        if ((output == null) || (outputOffset < 0) || (outputOffset > outputBufLen)) {
            throw new IllegalArgumentException("Output range is invalid");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSizeLegacy(inputLen, true /* isEncrypt */, tagLen);
        if ((outputBufLen - outputOffset) < len) {
            //OCKDebug.Msg (debPrefix, methodName,  "throwing ShortBufferException  outputlenth = " + output.length + " outputOffset=" + outputOffset + "len=" + len);
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        //OCKDebug.Msg(debPrefix, methodName, "key :", key);
        //OCKDebug.Msg(debPrefix, methodName, "iv :", iv);
        //OCKDebug.Msg(debPrefix, methodName, "input :", input);
        //OCKDebug.Msg(debPrefix, methodName, "aad :", aad);
        //OCKDebug.Msg(debPrefix, methodName,  "tagLen :" + tagLen + " inputOffset :" + inputOffset + "outputOffset :" + outputOffset);

        // Check if any part of the potential output overlaps the input area. If
        // so, then make a copy of a the input area
        // to work with so that the method is copy-safe. A copy will be made if
        // the input and output point to the same
        // array and if one of the following conditions is fulfilled:
        //
        // 1. If inputOffset == outputOffset
        // 2. If (inputOffset < outputOffset) and (outputOffset < (inputOffset +
        // inputLen))
        // 3. If (inputOffset > outputOffset) and (inputOffset < (outputOffset +
        // engineGetOutputSize(inputLen)))
        //
        if ((input == output) && (outputOffset - inputOffset < inputLen)) {
            // && (inputOffset - outputOffset < buffer.length)) {
            // copy 'input' out to avoid its content being
            // overwritten prematurely.
            input = Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen));
            inputOffset = 0;
        }

        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone(); // FIND THIS STRING  20220805

        int aadLen = authenticationData.length;

        if (CCMHardwareFunctionPtr == 0)
            CCMHardwareFunctionPtr = NativeInterface
                    .do_CCM_checkHardwareCCMSupport(ockContext.getId());

        if (iv.length + key.length + aadLen + tagLen <= FastJNIParameterBufferSize
                && (inputLen <= FastJNIInputBufferSize || CCMHardwareFunctionPtr != -1)) {

            FastJNIBuffer parameters = CCMCipher.parameterBuffer.get();
            parameters.put(0, iv, 0, ivLen);
            parameters.put(ivLen, authenticationData, 0, aadLen);

            //OCKDebug.Msg (debPrefix, methodName, "FastJNI key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
            //OCKDebug.Msg (debPrefix, methodName, " inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen :" + tagLen);

            if (CCMHardwareFunctionPtr != -1) { // hardware supports fast CCM command
                rc = useHardwareCCM(true, inputLen, ivLen, keyLen, aadLen, tagLen, key, input,
                        inputOffset, output, outputOffset, parameters);
            } else {
                FastJNIBuffer outputBuffer = CCMCipher.outputBuffer.get();
                FastJNIBuffer inputBuffer = CCMCipher.inputBuffer.get();
                inputBuffer.put(0, input, inputOffset, inputLen);
                parameters.put(ivLen + aadLen, key, 0, keyLen);
                rc = NativeInterface.do_CCM_encryptFastJNI(ockContext.getId(), keyLen, ivLen,
                        inputLen, output.length, aadLen, tagLen, parameters.pointer(),
                        inputBuffer.pointer(), outputBuffer.pointer());

                // Copy Output + Tag out of native data buffer
                outputBuffer.get(0, output, outputOffset, len);
            }
            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            }

        } else {

            // Create tempInput
            byte[] tempInput = new byte[input.length - inputOffset];
            // Copy contents of input from inputOffset for length inputLen into tempInput
            System.arraycopy(input, inputOffset, tempInput, 0, input.length - inputOffset);

            // Create tempOutput
            byte[] tempOutput = new byte[len + outputOffset]; // len from call to getOutputSizeLegacy() above

            rc = NativeInterface.do_CCM_encrypt(ockContext.getId(), iv, iv.length, key, key.length,
                    authenticationData, aadLen, tempInput, tempInput.length, tempOutput,
                    tempOutput.length, tagLen);

            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            } else {
                // Copy contents of tempOutput to output at outputOffset for len bytes
                // len is at least output.length + outputOffset
                System.arraycopy(tempOutput, 0, output, outputOffset, len);
            }
        }
        //OCKDebug.Msg(debPrefix, methodName,  "outLen=" + outLen + " output=",  output);
        return len;
    }


    /*
     * This method will be called by init/doFinal with no update calls. This won't
     * look at what is buffered.
     */
    public static int getOutputSizeLegacy(int inputLen, boolean encrypting, int tLen) {
        //final String methodName = "getOutputSizeLegacy :";

        if (!encrypting) {
            // if decrypting, will only need output buffer size atmost size of
            // input
            return inputLen - tLen;
        } else {
            // if encrypting, will need at most input size and space for tag
            //OCKDebug.Msg (debPrefix, methodName, "returning " + (inputLen + tLen));
            return inputLen + tLen;
        }
    }


    public static int getOutputSize(int inputLen, boolean encrypting, int tLen) {
        return getOutputSize(inputLen, encrypting, tLen, true);
    }


    private static int getOutputSize(int inputLen, boolean encrypting, int tLen,
            boolean isDoFinal) {

        int totalLen = inputLen;
        //final String methodName = "getOutputSize :";
        if (isDoFinal) {
            if (!encrypting) {
                // if decrypting, will only need output buffer size atmost size of
                // input
                totalLen = inputLen - tLen;
            } else {
                // if encrypting, will need at most input size and space for tag
                ////OCKDebug.Msg (debPrefix, methodName, "returning " + (inputLen + tLen));
                totalLen = inputLen + tLen;
            }
        }
        if (totalLen < 0)
            totalLen = 0;
        //OCKDebug.Msg (debPrefix, methodName, "getOutputSize  totalLen=" + totalLen);
        return totalLen;
    }


    public static void doCCM_cleanup(OCKContext ockContext) throws OCKException {
        if (ockContext != null) {
            NativeInterface.do_CCM_delete(ockContext.getId());
        }
    }


    static long getMode(boolean isEncrypt, int keyLen) {
        // Configure mode
        long mode = 0;
        switch (keyLen * 8) {
            case 128:
                mode = CCM_MODE_128;
                break;
            case 192:
                mode = CCM_MODE_192;
                break;
            case 256:
                mode = CCM_MODE_256;
                break;
        }
        if (!isEncrypt)
            mode += CCM_MODE_DECRYPT;
        mode += CCM_AUGMENTED_MODE;
        return mode;
    }


    static int useHardwareCCM(boolean isEncrypt, int inputLen, int ivLen, int keyLen, int aadLen,
            int tagLen, byte[] key, byte[] input, int inputOffset, byte[] output, int outputOffset,
            FastJNIBuffer parameters)
            throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, AEADBadTagException {

        int rc = 0;
        // Setting offsets and inputLen
        final int modeOffset = ivLen + aadLen + tagLen;
        final int paramBlockOffset = modeOffset + 8;
        if (!isEncrypt)
            inputLen -= tagLen;

        long mode = getMode(isEncrypt, keyLen);
        parameters.put(modeOffset, longToBytes(mode), 0, 8); // Allocating 8 bytes for mode

        // Adding paramBlock for asm routine
        byte[] addedParams = new byte[parameterBlockSize + keyLen];
        System.arraycopy(key, 0, addedParams, keyOffset, keyLen); // Add key
        putLongtoByteArray(aadLen * 8, addedParams, TAADLOffset); // Add TAADL (total aad length)
        putLongtoByteArray(inputLen * 8, addedParams, TPCLOffset); // Add TPCL
        parameters.put(paramBlockOffset, addedParams, 0, addedParams.length);

        if (isEncrypt) { // encrypt
            rc = NativeInterface.do_CCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen, 0,
                    inputLen, 0, aadLen, tagLen, parameters.pointer(), input, inputOffset, output,
                    outputOffset);
        } else { // decrypt
            rc = NativeInterface.do_CCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, 0,
                    inputLen, 0, aadLen, tagLen, parameters.pointer(), input, inputOffset, output,
                    outputOffset);
            if (rc == -1)
                throw new AEADBadTagException("Tag mismatch!");
        }
        return rc;
    }


    public static void putLongtoByteArray(long number, byte[] bArray, int startIndex) {
        bArray[startIndex] = (byte) (number >>> 56);
        bArray[startIndex + 1] = (byte) (number >>> 48);
        bArray[startIndex + 2] = (byte) (number >>> 40);
        bArray[startIndex + 3] = (byte) (number >>> 32);
        bArray[startIndex + 4] = (byte) (number >>> 24);
        bArray[startIndex + 5] = (byte) (number >>> 16);
        bArray[startIndex + 6] = (byte) (number >>> 8);
        bArray[startIndex + 7] = (byte) number;
    }


    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }


    /** * Converts a byte array to hex string */
    public static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
                'E', 'F'};
        int len = block.length;
        int high = 0;
        int low = 0;

        for (int i = 0; i < len; i++) {
            if (i % 16 == 0)
                buf.append('\n');
            high = ((block[i] & 0xf0) >> 4);
            low = (block[i] & 0x0f);
            buf.append(hexChars[high]);
            buf.append(hexChars[low]);
            buf.append(' ');
        }

        return buf.toString();
    }

}
