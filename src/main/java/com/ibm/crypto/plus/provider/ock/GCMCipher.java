/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

public final class GCMCipher {

    private static final String DISABLE_GCM_ACCELERATION = "com.ibm.crypto.provider.DisableGCMAcceleration";
    private static final boolean disableGCMAcceleration = Boolean.parseBoolean(System.getProperty(DISABLE_GCM_ACCELERATION));
    private static final String debPrefix = "GCMCipher";
    private static long GCMHardwareFunctionPtr = 0;

    static final int parameterBlockSize = 80;
    static final int TAADLOffset = 48;
    static final int TPCLOffset = 56;
    static final int keyOffset = 80;

    static final int GCM_MODE_128 = 18;
    static final int GCM_MODE_192 = 19;
    static final int GCM_MODE_256 = 20;
    static final int GCM_MODE_DECRYPT = 128;
    static final int GCM_AUGMENTED_MODE = 768;

    // Buffer to pass GCM input to native
    private static final ThreadLocal<FastJNIBuffer> inputBuffer = new ThreadLocal<FastJNIBuffer>() {
        @Override
        protected FastJNIBuffer initialValue() {
            return FastJNIBuffer.create(FastJNIInputBufferSize);
        }
    };

    // Buffer to get GCM output from native
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

    // Buffer to maintain GCM contexts should the platform not be capable of
    // caching the GCM contexts itself in a thread safe manner
    //
    // each key size needs different cache since a GCM context initialized with a 16B key
    // cannot be used for any other key size without destroying it
    // Same story for FIPS mode contexts
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferE16 = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferE24 = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferE32 = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferE16FIPS = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferE24FIPS = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferE32FIPS = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferD16 = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferD24 = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferD32 = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferD16FIPS = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferD24FIPS = new ThreadLocal<GCMContextPointer>() {};
    private static final ThreadLocal<GCMContextPointer> gcmContextBufferD32FIPS = new ThreadLocal<GCMContextPointer>() {};
    private static final boolean useJavaTLS = true;

    private static final Map<Integer, String> ErrorCodes;
    static {
        ErrorCodes = new HashMap<Integer, String>();
        ErrorCodes.put(1, "ICC_AES_GCM_CTX_new failed");
        ErrorCodes.put(2, "ICC_AES_GCM_Init failed - Error initializing in En/Decrypt");
        ErrorCodes.put(3, "ICC_AES_GCM_En/DecryptUpdate failed");
        ErrorCodes.put(4, "ICC_AES_GCM_En/DecryptFinal failed");
        ErrorCodes.put(5, "NULL from GetPrimitiveArrayCritical");
        ErrorCodes.put(6, "ICC_AES_GCM_DecryptFinal failed: Tag Mismatch!\n");

        //        int tls_support_result;
        //        try {
        //            tls_support_result = NativeInterface.get_GCM_TLSEnabled();
        //        } catch (OCKException e) {
        //            tls_support_result = 1;
        //        }
        //        useJavaTLS = (tls_support_result != 0);
    }
    private static final int FastJNIInputBufferSize = 1024 * 2 * 2;
    private static final int FastJNIOutputBufferSize = 1024 * 2 * 2 + 16; //Add Tag length for encryption
    private static final int FastJNIParameterBufferSize = 1024;

    // AES-GCM constants in Bytes
    private static final int AES_GCM_MIN_KEY_SIZE = 16;
    private static final int AES_GCM_MIN_IV_SIZE = 1;
    private static final byte[] emptyAAD = new byte[0];

    // it is not synchronized since there are no shared OCK data structures used in the OCK call
    // except ICC_CTX which is thread safe
    public static int doGCMFinal_Decrypt(OCKContext ockContext, byte[] key, byte[] iv, int tagLen,
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset,
            byte[] aad, OpenJCEPlusProvider provider) throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, AEADBadTagException {
        //final String methodName="doGCMFinal_Decrypt ";
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

        if (key.length < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        if ((iv != null) && (iv.length < AES_GCM_MIN_IV_SIZE)) {
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

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSizeLegacy(inputLen, false /*isEncrypt*/, tagLen);
        if ((output == null) || ((output.length - outputOffset) < len)) {
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
        //byte[] copyOfInput = null;
        if ((input == output) && (outputOffset - inputOffset < inputLen)) {
            // && (inputOffset - outputOffset < buffer.length)) {
            // copy 'input' out to avoid its content being
            // overwritten prematurely.
            input = Arrays.copyOfRange(input, inputOffset, Math.addExact(inputOffset, inputLen));
            inputOffset = 0;
        }

        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(false, key.length, ockContext, provider);

        if (GCMHardwareFunctionPtr == 0)
            GCMHardwareFunctionPtr = NativeInterface
                    .do_GCM_checkHardwareGCMSupport(ockContext.getId());


        if (iv.length + key.length + aadLen <= FastJNIParameterBufferSize && !disableGCMAcceleration
                && (inputLen <= FastJNIInputBufferSize || GCMHardwareFunctionPtr != -1)) {
            FastJNIBuffer parameters = GCMCipher.parameterBuffer.get();
            parameters.put(0, iv, 0, iv.length);
            parameters.put(iv.length, authenticationData, 0, aadLen);

            if (GCMHardwareFunctionPtr != -1) { // hardware supports fast GCM command
                rc = useHardwareGCM(false, inputLen, iv.length, key.length, aadLen, tagLen, key,
                        input, inputOffset, output, outputOffset, parameters);
            } else {

                FastJNIBuffer outputBuffer = GCMCipher.outputBuffer.get();
                FastJNIBuffer inputBuffer = GCMCipher.inputBuffer.get();
                inputBuffer.put(0, input, inputOffset, inputLen);
                parameters.put(iv.length + aadLen, key, 0, key.length);

                rc = NativeInterface.do_GCM_decryptFastJNI(ockContext.getId(), gcmCtx,
                        key.length, iv.length, 0, inputLen - tagLen, 0, aadLen, tagLen,
                        parameters.pointer(), inputBuffer.pointer(), outputBuffer.pointer());
                // Copy Output + Tag out of native data buffer
                outputBuffer.get(0, output, outputOffset, len);
            }

            //OCKDebug.Msg (debPrefix, methodName, "RC = " + rc);
            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            }
        } else {
            rc = NativeInterface.do_GCM_decrypt(ockContext.getId(), gcmCtx, key, key.length, iv,
                    iv.length, input, inputOffset, inputLen - tagLen, output, outputOffset,
                    authenticationData, aadLen, tagLen);
            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            }
        }
        return len;
    }

    // it is not synchronized since there are no shared OCK data structures used in the OCK call
    // except ICC_CTX which is thread safe
    public static int doGCMFinal_Encrypt(OCKContext ockContext, byte[] key, byte[] iv, int tagLen,
            byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset,
            byte[] aad, OpenJCEPlusProvider provider) throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {

        //final String methodName = "doGCMFinal_Encrypt ";
        int outLen = 0;
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

        if (keyLen < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        int ivLen = iv.length;
        if (ivLen < AES_GCM_MIN_IV_SIZE) {
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

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSizeLegacy(inputLen, true /* isEncrypt */, tagLen);
        if ((outputBufLen - outputOffset) < len) {
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }

        //OCKDebug.Msg(debPrefix, methodName, "key :", key);
        //OCKDebug.Msg(debPrefix, methodName, "iv :", iv);
        //OCKDebug.Msg(debPrefix, methodName, "input :", iv);
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

        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(true, key.length, ockContext, provider);

        if (GCMHardwareFunctionPtr == 0)
            GCMHardwareFunctionPtr = NativeInterface
                    .do_GCM_checkHardwareGCMSupport(ockContext.getId());
        if (iv.length + key.length + aadLen + tagLen <= FastJNIParameterBufferSize
                && (inputLen <= FastJNIInputBufferSize || GCMHardwareFunctionPtr != -1)) {
            FastJNIBuffer parameters = GCMCipher.parameterBuffer.get();
            parameters.put(0, iv, 0, ivLen);
            parameters.put(ivLen, authenticationData, 0, aadLen);

            if (GCMHardwareFunctionPtr != -1) { // hardware supports fast GCM command
                rc = useHardwareGCM(true, inputLen, ivLen, keyLen, aadLen, tagLen, key, input,
                        inputOffset, output, outputOffset, parameters);
            } else {
                FastJNIBuffer outputBuffer = GCMCipher.outputBuffer.get();
                FastJNIBuffer inputBuffer = GCMCipher.inputBuffer.get();
                inputBuffer.put(0, input, inputOffset, inputLen);
                parameters.put(ivLen + aadLen, key, 0, keyLen);
                rc = NativeInterface.do_GCM_encryptFastJNI(ockContext.getId(), gcmCtx, keyLen,
                        ivLen, 0, inputLen, 0, aadLen, tagLen, parameters.pointer(),
                        inputBuffer.pointer(), outputBuffer.pointer());
                // Copy Output + Tag out of native data buffer
                outputBuffer.get(0, output, outputOffset, len);
            }
            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            }
            // Copy Tag out of native data buffer
            parameters.get(keyLen + ivLen + aadLen, output, outputOffset + inputLen, tagLen);

            outLen = inputLen + tagLen;
        } else {
            byte[] tag = new byte[tagLen];

            //OCKDebug.Msg (debPrefix, methodName,   "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
            //OCKDebug.Msg (debPrefix, methodName," inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen " + tagLen);
            rc = NativeInterface.do_GCM_encrypt(ockContext.getId(), gcmCtx, key, key.length, iv,
                    iv.length, input, inputOffset, inputLen, output, outputOffset,
                    authenticationData, aadLen, tag, tagLen);
            System.arraycopy(tag, 0, output, outputOffset + inputLen, tagLen);
            outLen = inputLen + tagLen;
            if (rc != 0) {
                throw new OCKException(ErrorCodes.get(rc));
            }
        }
        //OCKDebug.Msg(debPrefix, methodName,  "outLen=" + outLen + " output=",  output);
        return outLen;
    }

    public static int do_GCM_FinalForUpdateDecrypt(OCKContext ockContext, byte[] key, byte[] iv,
            int tagLen, byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, OpenJCEPlusProvider provider)
            throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, AEADBadTagException {
        //final String methodName="do_GCM_FinalForUpdateDecrypt ";
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

        if (key.length < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        if ((iv != null) && (iv.length < AES_GCM_MIN_IV_SIZE)) {
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

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSize(inputLen, false /*isEncrypt*/, tagLen, true);
        if (output.length - outputOffset < len) {
            //OCKDebug.Msg(debPrefix, methodName, "throwing ShortBufferException  outputlenth = " + output.length + " outputOffset=" + outputOffset + "len=" + len);
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }



        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(false, key.length, ockContext, provider);
        //OCKDebug.Msg(debPrefix,methodName, "gcmCtx = " + gcmCtx );

        //OCKDebug.Msg (debPrefix, methodName, "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
        //OCKDebug.Msg (debPrefix, methodName, " inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen :" + tagLen);
        //OCKDebug.Msg (debPrefix, methodName, "length of output :" + output.length + " outputOffset :" + outputOffset);

        //OCKDebug.Msg (debPrefix, methodName, "before calling do_GCM_FinalForUpdateDecrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        rc = NativeInterface.do_GCM_FinalForUpdateDecrypt(ockContext.getId(), gcmCtx, input,
                inputOffset, inputLen, output, outputOffset, output.length, authenticationData,
                aadLen, tagLen);

        //OCKDebug.Msg (debPrefix, methodName, "After calling do_GCM_FinalForUpdateDecrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        //OCKDebug.Msg (debPrefix, methodName, "Decrypted text from do_GCM_FinalForUpdateDecrypt = ",  output);
        if (rc != 0) {
            throw new OCKException(ErrorCodes.get(rc));
        }
        
        //OCKDebug.Msg (debPrefix, methodName, "Returning length= " +  len);
        return len;
    }


    public static int do_GCM_InitForUpdateDecrypt(OCKContext ockContext, byte[] key, byte[] iv,
            int tagLen, byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, OpenJCEPlusProvider provider)
            throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, AEADBadTagException {
        //final String methodName="do_GCM_InitForUpdateDecrypt ";
        int rc = 0;
        byte[] authenticationData;

        //OCKDebug.Msg(debPrefix, methodName,  "key :" + key);
        //OCKDebug.Msg(debPrefix, methodName,  "iv :" + iv);
        //OCKDebug.Msg(debPrefix, methodName,"input :" + input);
        //OCKDebug.Msg(debPrefix, methodName,"inputLen :" + inputLen);
        //OCKDebug.Msg(debPrefix, methodName, "aad :" + aad);
        //OCKDebug.Msg(debPrefix, methodName,  "tagLen :" + tagLen + " inputOffset :" + inputOffset + "outputOffset : " + outputOffset );

        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }

        if ((iv == null)) {
            throw new IllegalArgumentException("IV is null");
        }

        if (key.length < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        if ((iv != null) && (iv.length < AES_GCM_MIN_IV_SIZE)) {
            throw new IllegalArgumentException("IV is the wrong size");
        }



        if ((output == null) || (outputOffset < 0) || (outputOffset > output.length)) {
            throw new IllegalArgumentException("Output range is invalid");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = 0;



        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(false, key.length, ockContext, provider);
        //OCKDebug.Msg(debPrefix,methodName, "gcmCtx = " + gcmCtx );

        //To-Do - replace false with actual logic
    
        //OCKDebug.Msg (debPrefix, methodName, "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
        //OCKDebug.Msg (debPrefix, methodName, " inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen :" + tagLen);
        //OCKDebug.Msg (debPrefix, methodName, "outputOffset :" + String.valueOf(outputOffset));
        //OCKDebug.Msg (debPrefix, methodName, "before calling do_GCM_UpdateDecrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        rc = NativeInterface.do_GCM_InitForUpdateDecrypt(ockContext.getId(), gcmCtx, key,
                key.length, iv, iv.length, authenticationData, aadLen);

        //OCKDebug.Msg (debPrefix, methodName, "After calling do_GCM_InitForUpdateDecrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        if (rc != 0) {
            throw new OCKException(ErrorCodes.get(rc));
        }
        //OCKDebug.Msg (debPrefix, methodName, "Native do_GCM_InitForUpdateDecrypt returns  output offset=" + outputOffset + " output=", output);

        return len;
    }

    public static /*synchronized*/ int do_GCM_UpdForUpdateDecrypt(OCKContext ockContext, byte[] key,
            byte[] iv, int tagLen, byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, OpenJCEPlusProvider provider)
            throws OCKException, IllegalStateException, ShortBufferException,
            IllegalBlockSizeException, BadPaddingException, AEADBadTagException {
        //final String methodName="do_GCM_UpdForUpdateDecrypt ";
        int rc = 0;


        //OCKDebug.Msg(debPrefix, methodName,  "key :" + key);
        //OCKDebug.Msg(debPrefix, methodName,  "iv :" + iv);
        //OCKDebug.Msg(debPrefix, methodName,"input :" + input);
        //OCKDebug.Msg(debPrefix, methodName,"inputLen :" + inputLen);
        //OCKDebug.Msg(debPrefix, methodName, "aad :" + aad);
        //OCKDebug.Msg(debPrefix, methodName,  "tagLen :" + tagLen + " inputOffset :" + inputOffset + "outputOffset : " + outputOffset );

        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }

        if ((iv == null)) {
            throw new IllegalArgumentException("IV is null");
        }

        if (key.length < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        if ((iv != null) && (iv.length < AES_GCM_MIN_IV_SIZE)) {
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

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSize(inputLen, false /*isEncrypt*/, tagLen, false);
        //OCKDebug.Msg(debPrefix, methodName, "output buffer len = " + len);


        //authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        //int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(false, key.length, ockContext, provider);

        //OCKDebug.Msg(debPrefix,methodName, "gcmCtx = " + gcmCtx );

        //OCKDebug.Msg (debPrefix, methodName, "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
        //OCKDebug.Msg (debPrefix, methodName, " inputLen :" + inputLen + " tagLen :" + tagLen);
        //OCKDebug.Msg (debPrefix, methodName, "outputOffset :" + String.valueOf(outputOffset));
        //OCKDebug.Msg (debPrefix, methodName, "before calling do_GCM_UpdForUpdateDecrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        rc = NativeInterface.do_GCM_UpdForUpdateDecrypt(ockContext.getId(), gcmCtx, input,
                inputOffset, inputLen, //inputLen-tagLen,
                output, outputOffset);
        //                //OCKDebug.Msg (debPrefix, methodName, "rc =" + rc + " After calling do_GCM_UpdForUpdateDecrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));

        if (rc != 0) {
            throw new OCKException(ErrorCodes.get(rc));
        }
        //              //OCKDebug.Msg (debPrefix, methodName, "Native do_GCM_UpdForUpdateDecrypt returns  output offset=" + outputOffset + " output=", output);

        return len;
    }

    public static int do_GCM_FinalForUpdateEncrypt(OCKContext ockContext, byte[] key, byte[] iv,
            int tagLen, byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, OpenJCEPlusProvider provider) throws OCKException, IllegalStateException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        //final String methodName = "do_GCM_FinalForUpdateEncrypt ";
        int outLen = 0;
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

        if (keyLen < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        int ivLen = iv.length;
        if (ivLen < AES_GCM_MIN_IV_SIZE) {
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

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSize(inputLen, true /* isEncrypt */, tagLen, true);
        if (outputBufLen - outputOffset < len) {
            //OCKDebug.Msg(debPrefix, methodName,  "throwing ShortBufferException  outputlenth = " + output.length + " outputOffset=" + outputOffset + "len=" + len);
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }
        //OCKDebug.Msg(debPrefix, methodName, "Got past all the length checks");
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


        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(true, key.length, ockContext, provider);
        //OCKDebug.Msg (debPrefix, methodName, "gcmCtx :" + String.valueOf(gcmCtx));


        byte[] tag = new byte[tagLen];

        //OCKDebug.Msg (debPrefix, methodName, "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
        //OCKDebug.Msg (debPrefix, methodName, " inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen " + tagLen);
        //OCKDebug.Msg (debPrefix, methodName, "before calling do_GCM_FinalForUpdateEncrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()) + " input[]=", input);
        rc = NativeInterface.do_GCM_FinalForUpdateEncrypt(ockContext.getId(), gcmCtx, key,
                key.length, iv, iv.length, input, inputOffset, inputLen, output, outputOffset,
                authenticationData, aadLen, tag, tagLen);

        //OCKDebug.Msg(debPrefix, methodName,  " System array copy myoutput=",  myoutput);
        System.arraycopy(tag, 0, output, (outputOffset + inputLen), tagLen);

        outLen = inputLen + tagLen;

        if (rc != 0) {
            throw new OCKException(ErrorCodes.get(rc));
        }
        //OCKDebug.Msg (debPrefix, methodName, "output from native do_GCM_FinalForUpdateEncrypt=", output);

        //}
        //OCKDebug.Msg(debPrefix, methodName,  "outLen=" + outLen + " output=",  output);
        return outLen;
    }

    // it is not synchronized since there are no shared OCK data structures used in the OCK call
    // except ICC_CTX which is thread safe
    public static int do_GCM_UpdForUpdateEncrypt(OCKContext ockContext, byte[] key, byte[] iv,
            int tagLen, byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, OpenJCEPlusProvider provider) throws OCKException, IllegalStateException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        //final String methodName = "do_GCM_UpdForUpdateEncrypt ";
        int outLen = 0;
        int outputBufLen = output.length;
        int rc = 0;
        if ((key == null) || (key.length == 0)) {
            throw new IllegalArgumentException("key is null/empty");
        }
        int keyLen = key.length;

        if (iv == null) {
            throw new IllegalArgumentException("IV is null");
        }

        if (keyLen < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        int ivLen = iv.length;
        if (ivLen < AES_GCM_MIN_IV_SIZE) {
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

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSize(inputLen, true /* isEncrypt */, tagLen, false);
        if (outputBufLen - outputOffset < len) {
            //OCKDebug.Msg (debPrefix, methodName,  "throwing ShortBufferException  outputlenth = " + output.length + " outputOffset=" + outputOffset + "len=" + len);
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");

        }

        //OCKDebug.Msg(debPrefix, methodName, "passed intial length checks");
        //OCKDebug.Msg(debPrefix, methodName, "key :", key);
        //OCKDebug.Msg(debPrefix, methodName, "iv :", iv);
        //OCKDebug.Msg(debPrefix, methodName, "input :", input);
        //OCKDebug.Msg(debPrefix, methodName, "aad :", aad);
        //OCKDebug.Msg(debPrefix, methodName,  "tagLen :" + tagLen + " inputOffset :" + inputOffset + "outputOffset :" + outputOffset);



        //OCKDebug.Msg(debPrefix, methodName, "checking of overlapping input/output array completed");
        //authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        // int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(true, key.length, ockContext, provider);
        //OCKDebug.Msg(debPrefix, methodName, " gcmCtx " + gcmCtx);
        //To-Do and implement actual logic

        //OCKDebug.Msg (debPrefix, methodName, "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
        //OCKDebug.Msg (debPrefix, methodName, "calling native interface: inputLen :" + inputLen + " tagLen " + tagLen);
        //OCKDebug.Msg (debPrefix, methodName, "before calling do_GCM_UpdForUpdateEncrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        rc = NativeInterface.do_GCM_UpdForUpdateEncrypt(ockContext.getId(), gcmCtx, input,
                inputOffset, inputLen, output, outputOffset);
        //OCKDebug.Msg (debPrefix, methodName, "After calling do_GCM_UpdForUpdateEncrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        //OCKDebug.Msg(debPrefix, methodName,  "back from Native interface=" + rc);

        outLen = inputLen;

        if (rc != 0) {
            throw new OCKException(ErrorCodes.get(rc));
        }

        //OCKDebug.Msg(debPrefix, methodName,  "outLen=" + outLen + " output=",  output);
        return outLen;
    }

    // it is not synchronized since there are no shared OCK data structures used in the OCK call
    // except ICC_CTX which is thread safe
    public static int do_GCM_InitForUpdateEncrypt(OCKContext ockContext, byte[] key, byte[] iv,
            int tagLen, byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, byte[] aad, OpenJCEPlusProvider provider) throws OCKException, IllegalStateException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        //final String methodName = "do_GCM_InitForUpdateEncrypt ";
        int outLen = 0;
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

        if (keyLen < AES_GCM_MIN_KEY_SIZE) {
            throw new IllegalArgumentException("key is the wrong size");
        }

        int ivLen = iv.length;
        if (ivLen < AES_GCM_MIN_IV_SIZE) {
            throw new IllegalArgumentException("IV is the wrong size");
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        // if Encrypting, the output buffer size should be cipherSize + TAG
        // if Decrypting, the output buffer size should be cipherSize - TAG
        int len = getOutputSize(inputLen, true /* isEncrypt */, tagLen, false);
        if (outputBufLen - outputOffset < len) {
            //OCKDebug.Msg (debPrefix, methodName,  "throwing ShortBufferException  outputlenth = " + output.length + " outputOffset=" + outputOffset + "len=" + len);
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");

        }

        //OCKDebug.Msg(debPrefix, methodName, "passed intial length checks");
        //OCKDebug.Msg(debPrefix, methodName, "key :", key);
        //OCKDebug.Msg(debPrefix, methodName, "iv :", iv);
        //OCKDebug.Msg(debPrefix, methodName, "input :", input);
        //OCKDebug.Msg(debPrefix, methodName, "aad :", aad);
        //OCKDebug.Msg(debPrefix, methodName,  "tagLen :" + tagLen + " inputOffset :" + inputOffset + "outputOffset :" + outputOffset);



        //OCKDebug.Msg(debPrefix, methodName, "checking of overlapping input/output array completed");
        authenticationData = (aad != null) ? aad.clone() : emptyAAD.clone();

        int aadLen = authenticationData.length;

        long gcmCtx = getGCMContext(true, key.length, ockContext, provider);
        //OCKDebug.Msg(debPrefix, methodName, " gcmCtx " + gcmCtx);

        //OCKDebug.Msg (debPrefix, methodName, "key.length :" + key.length + " iv.length :" + iv.length + " inputOffset :" + inputOffset);
        //OCKDebug.Msg (debPrefix, methodName, "calling native interface: inputLen :" + inputLen + " aadLen :" + aadLen + " tagLen " + tagLen);
        //OCKDebug.Msg (debPrefix, methodName, "before calling do_GCM_InitForUpdateEncrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        rc = NativeInterface.do_GCM_InitForUpdateEncrypt(ockContext.getId(), gcmCtx, key,
                key.length, iv, iv.length, authenticationData, aadLen);
        //OCKDebug.Msg (debPrefix, methodName, "After calling do_GCM_InitForUpdateEncrypt gcmUpdateOutlen ="  + String.valueOf(gcmUpdateOutlen.getValue()));
        //OCKDebug.Msg(debPrefix, methodName,  "back from Native interface=" + rc);

        outLen = 0;

        if (rc != 0) {
            throw new OCKException(ErrorCodes.get(rc));
        }
        
        //OCKDebug.Msg(debPrefix, methodName,  "outLen=" + outLen + " output=",  output);
        return outLen;
    }


    private static long getGCMContext(boolean encrypting, int keyLength, OCKContext ockContext, OpenJCEPlusProvider provider)
            throws OCKException {
        //// if it is indicated that Java based TLS storage of GCM contexts should be used
        //// we fetch the TLS copy of the gcm context. if uninitialized, create a new one
        if (useJavaTLS) {
            GCMContextPointer gcmCtx = null;
            int keyLength_ = keyLength + ((ockContext.isFIPS()) ? 1 : 0);
            ThreadLocal<GCMContextPointer> gcmCtxBuffer = null;
            switch (keyLength_) {
                case 16:
                    gcmCtxBuffer = (encrypting) ? gcmContextBufferE16 : gcmContextBufferD16;
                    break;
                case 17:
                    gcmCtxBuffer = (encrypting) ? gcmContextBufferE16FIPS : gcmContextBufferD16FIPS;
                    break;
                case 24:
                    gcmCtxBuffer = (encrypting) ? gcmContextBufferE24 : gcmContextBufferD24;
                    break;
                case 25:
                    gcmCtxBuffer = (encrypting) ? gcmContextBufferE24FIPS : gcmContextBufferD24FIPS;
                    break;
                case 32:
                    gcmCtxBuffer = (encrypting) ? gcmContextBufferE32 : gcmContextBufferD32;
                    break;
                case 33:
                    gcmCtxBuffer = (encrypting) ? gcmContextBufferE32FIPS : gcmContextBufferD32FIPS;
                    break;
            }
            gcmCtx = gcmCtxBuffer.get();
            if (gcmCtx == null) {
                gcmCtx = new GCMContextPointer(ockContext.getId(), provider);
                gcmCtxBuffer.set(gcmCtx);
            }
            return gcmCtx.getCtx();
        } else {
            return 0;
        }
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
        //int totalLen = inputLen;

        return getOutputSize(inputLen, encrypting, tLen, true);
    }

    private static int getOutputSize(int inputLen, boolean encrypting, int tLen,
            boolean isDoFinal) {
        int totalLen = inputLen;

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

    public static void doGCM_cleanup(OCKContext ockContext) throws OCKException {
        if (ockContext != null) {
            NativeInterface.do_GCM_delete(ockContext.getId());
        }
    }



    static long getMode(boolean isEncrypt, int keyLen) {
        // Configure mode
        long mode = 0;
        switch (keyLen * 8) {
            case 128:
                mode = GCM_MODE_128;
                break;
            case 192:
                mode = GCM_MODE_192;
                break;
            case 256:
                mode = GCM_MODE_256;
                break;
        }
        if (!isEncrypt)
            mode += GCM_MODE_DECRYPT;
        mode += GCM_AUGMENTED_MODE;
        return mode;
    }

    static int useHardwareGCM(boolean isEncrypt, int inputLen, int ivLen, int keyLen, int aadLen,
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
            rc = NativeInterface.do_GCM_encryptFastJNI_WithHardwareSupport(keyLen, ivLen, 0,
                    inputLen, 0, aadLen, tagLen, parameters.pointer(), input, inputOffset, output,
                    outputOffset);
        } else { // decrypt
            rc = NativeInterface.do_GCM_decryptFastJNI_WithHardwareSupport(keyLen, ivLen, 0,
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

    public static byte[] intToBytes(int x) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(x);
        return buffer.array();
    }

    static class GCMContextPointer {
        OpenJCEPlusProvider provider;
        final long gcmCtx;
        long ockContext = 0;

        GCMContextPointer(long ockContext, OpenJCEPlusProvider provider) throws OCKException {
            this.gcmCtx = NativeInterface.create_GCM_context(ockContext);
            this.ockContext = ockContext;
            this.provider = provider;

            this.provider.registerCleanable(this, cleanOCKResources(gcmCtx, ockContext));
        }

        long getCtx() {
            return gcmCtx;
        }

        private Runnable cleanOCKResources(long gcmCtx, long ockContext){
            return() -> {
                try {
                    if (gcmCtx != 0) {
                        NativeInterface.free_GCM_ctx(ockContext, gcmCtx);
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

    public static boolean gcmUpdateSupported() {
        boolean supported = false;
        String osName = NativeInterface.getOsName();

        if (osName.startsWith("Windows")) {
            supported = true;
        } else if (osName.equals("Linux")) {
            supported = true;
        } else if (osName.equals("AIX")) {
            supported = true;
        } else if (osName.equals("Mac OS X")) {
            supported = true;
        } else if (osName.equals("z/OS")) {
            supported = true;
        }

        return supported;
    }

}
