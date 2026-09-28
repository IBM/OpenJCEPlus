/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLCCM.c
 * @brief Implementation of CCM (Counter with CBC-MAC) authenticated encryption.
 *
 * This file implements AES-CCM mode operations using OpenSSL's EVP interface.
 * CCM mode combines CTR mode encryption with CBC-MAC authentication to provide
 * both confidentiality and authenticity in a single operation.
 *
 * Key features:
 * - Supports AES-128, AES-192, and AES-256
 * - Configurable tag lengths (4-16 bytes, must be even)
 * - Configurable nonce/IV lengths (7-13 bytes)
 * - Additional Authenticated Data (AAD) support
 * - Streaming and single-shot operations
 *
 * CCM mode is specified in NIST SP 800-38C and is commonly used in
 * protocols like IEEE 802.15.4, Bluetooth LE, and IPsec.
 *
 * @note CCM requires the plaintext length to be known before processing AAD,
 *       which is handled automatically in the encryptFinal and decryptFinal
 *       functions.
 */

#include <jni.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

/* CCM constants */
#define MAX_CCM_TAG_SIZE        16
#define MIN_CCM_TAG_SIZE        4
#define MAX_CCM_IV_SIZE         13
#define MIN_CCM_IV_SIZE         7
/* OPENSSL_TAG_MISMATCH_ERROR is defined in OpenSSLGCM.h - do not redefine */

#include "OpenSSLGCM.h"
#include "OpenSSLContext.h"
#include "OpenSSLSymmetricCipher.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLLogging.h"
#include "OpenSSLHelpers.h"

//============================================================================
// CCM_init - Initialize CCM cipher with key, IV, and tag length
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1init(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_init";
    CipherContext*     cipherCtx    = NULL;
    EVP_CIPHER_CTX*    ctx;
    jbyte*             keyBytes;
    jbyte*             ivBytes;
    int                ivLen;
    int                encryptFlag;

    logFunctionEntry(functionName);

    /* Validate tag length (must be in range and even) */
    if (!validateIntRange(
            env, tagLen, MIN_CCM_TAG_SIZE, MAX_CCM_TAG_SIZE, functionName,
            "Invalid CCM tag length: must be 4-16 bytes and even")) {
        return;
    }
    if (tagLen % 2 != 0) {
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid CCM tag length: must be even");
        logFunctionExit(functionName);
        return;
    }

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return;
    }

    ctx = cipherCtx->ctx;

    keyBytes = getByteArrayElementsSafe(env, key, functionName, "key");
    if (keyBytes == NULL) {
        logFunctionExit(functionName);
        return;
    }

    ivBytes = getByteArrayElementsSafe(env, iv, functionName, "IV");
    if (ivBytes == NULL) {
        /* C-5: getByteArrayElementsSafe already set the exception */
        cleanupByteArray(env, key, keyBytes, JNI_ABORT);
        logFunctionExit(functionName);
        return;
    }

    /* Validate IV length */
    if (!validateArrayLength(env, iv, MIN_CCM_IV_SIZE, MAX_CCM_IV_SIZE,
                             functionName,
                             "Invalid CCM IV length: must be 7-13 bytes")) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        return;
    }

    ivLen = (*env)->GetArrayLength(env, iv);

    encryptFlag = (encrypt != 0) ? 1 : 0;

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM_init: mode=%s, ivLen=%d, tagLen=%d",
            encryptFlag ? "encrypt" : "decrypt", ivLen, tagLen);
        // NOTE: Key material is never logged, even in debug mode, for security
    }
#endif

    /* Reset context to ensure clean state when reinitializing a cached context */
    if (EVP_CIPHER_CTX_reset(ctx) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to reset CCM cipher context");
        logOpenSSLError("EVP_CIPHER_CTX_reset");
        logFunctionExit(functionName);
        return;
    }

    if (EVP_CipherInit_ex(ctx, cipherCtx->cipher, NULL, NULL, NULL,
                          encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "OpenSSL Failed to initialize CCM cipher");
        logOpenSSLError("EVP_CipherInit_ex");
        logFunctionExit(functionName);
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, ivLen, NULL) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "OpenSSL Failed to set CCM IV length");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_IVLEN)");
        logFunctionExit(functionName);
        return;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tagLen, NULL) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "OpenSSL Failed to set CCM tag length");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_TAG)");
        logFunctionExit(functionName);
        return;
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char*)keyBytes,
                          (unsigned char*)ivBytes, encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "OpenSSL Failed to set CCM key and IV");
        logOpenSSLError("EVP_CipherInit_ex");
        logFunctionExit(functionName);
        return;
    }

    cipherCtx->tagLen      = tagLen;
    cipherCtx->updateCount = 0;  /* reset for each new CCM operation */

    cleanupByteArrays(env, key, keyBytes, iv, ivBytes);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL CCM cipher initialized successfully");
    }
#endif

    logFunctionExit(functionName);
}

//============================================================================
// CCM_update - Process data and AAD through CCM cipher
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1update(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_update";
    CipherContext*     cipherCtx    = NULL;
    EVP_CIPHER_CTX*    ctx;
    int                outLen;
    jsize              inputLength;
    jbyte*             inputBytes;
    jbyte*             outputBytes;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    ctx = cipherCtx->ctx;

    /* OpenSSL CCM mode only supports a single EVP_CipherUpdate call for data.
     * A second call with a new plaintext length re-announces the length and
     * resets CBC-MAC state, silently producing wrong authentication tags.
     * Reject any attempt to call CCM_update more than once per init. */
    if (cipherCtx->updateCount > 0) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "CCM_update called more than once per operation: "
                              "OpenSSL CCM requires all plaintext in a single update call");
        logFunctionExit(functionName);
        return -1;
    }
    cipherCtx->updateCount++;

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL CCM_update: inputLen=%d, aadLen=%d",
                     inputLen, aadLen);
    }
#endif

    /* CCM requires the total plaintext length to be declared before any
     * AAD or ciphertext is processed (NIST SP 800-38C requirement).
     * Pass (NULL, NULL, inputLen) to announce the length. */
    outLen = 0;
    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, inputLen) != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to set CCM plaintext length in update");
        logOpenSSLError("EVP_CipherUpdate(set plaintext length)");
        logFunctionExit(functionName);
        return -1;
    }

    // Process AAD using helper function
    if (!processAADFromArray(env, ctx, aad, aadLen, functionName)) {
        return -1;
    }

    inputLength = (*env)->GetArrayLength(env, input);

    if (!validateOffsetAndLength(env, inputLength, inputOffset, inputLen,
                                 functionName, "input")) {
        logFunctionExit(functionName);
        return -1;
    }

    inputBytes = getByteArrayElementsSafe(env, input, functionName, "input");
    if (inputBytes == NULL) {
        logFunctionExit(functionName);
        return -1;
    }

    /* Validate output bounds using the shared helper that is safe against
     * jint overflow in the addition outputOffset + inputLen.  The previous
     * inline check had an INT_MAX guard but was still susceptible to the
     * signed-integer overflow corner case when outputOffset itself is large. */
    if (!validateOutputBuffer(env, output, outputOffset, inputLen, functionName,
                              "Invalid parameters or output buffer too small")) {
        cleanupIOArrays(env, input, inputBytes, NULL, NULL, JNI_FALSE);
        return -1;
    }

    outputBytes = getByteArrayElementsSafe(env, output, functionName, "output");
    if (outputBytes == NULL) {
        cleanupIOArrays(env, input, inputBytes, NULL, NULL, JNI_FALSE);
        logFunctionExit(functionName);
        return -1;
    }

    outLen = 0;

    if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                         &outLen, (unsigned char*)(inputBytes + inputOffset),
                         inputLen) != 1) {
        cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_FALSE);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to update CCM cipher");
        logOpenSSLError("EVP_CipherUpdate");
        logFunctionExit(functionName);
        return -1;
    }

    cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_TRUE);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM update: processed %d bytes, output %d "
            "bytes",
            inputLen, outLen);
    }
#endif

    logFunctionExit(functionName);

    return outLen;
}

//============================================================================
// CCM_encryptFinal - Finalize CCM encryption and generate authentication tag
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_encryptFinal";
    CipherContext*     cipherCtx    = NULL;
    EVP_CIPHER_CTX*    ctx;
    int                totalOutLen = 0;
    int                outLen;
    int                requiredOutputSize;
    jbyte*             outputBytes;
    jbyte*             inputBytes;
    int                finalLen;
    unsigned char      tag[MAX_CCM_TAG_SIZE];

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    /* Verify tagLen matches the value fixed at CCM_init time.
     * OpenSSL's internal CBC-MAC was computed for cipherCtx->tagLen; using a
     * different value here would produce a silently-wrong or truncated tag. */
    if (tagLen != cipherCtx->tagLen) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "CCM tagLen mismatch: encryptFinal tagLen differs from CCM_init tagLen");
        logFunctionExit(functionName);
        return -1;
    }

    ctx = cipherCtx->ctx;

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM_encryptFinal: inputLen=%d, tagLen=%d",
            inputLen, tagLen);
    }
#endif

    /* For CCM, set plaintext length before processing AAD */
    outLen = 0;

    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, inputLen) != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to set CCM plaintext length");
        logOpenSSLError("EVP_CipherUpdate(set plaintext length)");
        logFunctionExit(functionName);
        return -1;
    }

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL Set CCM plaintext length: %d bytes",
                     inputLen);
    }
#endif

    // Process AAD if present
    if (!processAADFromArray(env, ctx, aad, aadLen, functionName)) {
        return -1;
    }

    // Validate output buffer size (ciphertext + tag).
    // Use validateOutputBuffer() rather than an inline check: the inline form
    // can overflow when outputOffset + (inputLen + tagLen) wraps a jint,
    // silently passing a bounds check that should have rejected the call.
    // Guard against jint overflow in inputLen + tagLen before the addition.
    if ((jlong)inputLen + (jlong)tagLen > (jlong)INT_MAX) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "Output buffer size overflow: inputLen + tagLen exceeds INT_MAX");
        logFunctionExit(functionName);
        return -1;
    }
    requiredOutputSize = inputLen + tagLen;
    if (!validateOutputBuffer(env, output, outputOffset, requiredOutputSize,
                              functionName,
                              "Output buffer too small or invalid offset")) {
        logFunctionExit(functionName);
        return -1;
    }
    outputBytes = getByteArrayElementsSafe(env, output, functionName, "output");
    if (outputBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        logFunctionExit(functionName);
        return -1;
    }

    // Process input if present
    if (inputLen > 0) {
        jsize inputArrayLen = (*env)->GetArrayLength(env, input);
        if (!validateOffsetAndLength(env, inputArrayLen, inputOffset, inputLen,
                                     functionName, "input")) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            logFunctionExit(functionName);
            return -1;
        }

        inputBytes =
            getByteArrayElementsSafe(env, input, functionName, "input");
        if (inputBytes == NULL) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get input bytes");
            logFunctionExit(functionName);
            return -1;
        }

        outLen = 0;

        if (EVP_CipherUpdate(
                ctx, (unsigned char*)(outputBytes + outputOffset), &outLen,
                (unsigned char*)(inputBytes + inputOffset), inputLen) != 1) {
            cleanupIOArrays(env, input, inputBytes, output, outputBytes,
                            JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process final input");
            logOpenSSLError("EVP_CipherUpdate");
            logFunctionExit(functionName);
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        totalOutLen += outLen;

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_CCM OpenSSL Processed %d bytes of final input, output "
                "%d bytes",
                inputLen, outLen);
        }
#endif
    } else {
        // For zero-length plaintext: CCM mode in OpenSSL does not support
        // EVP_CipherFinal_ex. The single EVP_CipherUpdate call with a valid
        // (empty) buffer and inputLen=0 completes the CBC-MAC and produces
        // the tag. Passing an empty byte array (not NULL) avoids JNI issues.
        unsigned char emptyBuf[1] = {0};
        outLen = 0;

        if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                             &outLen, emptyBuf, 0) != 1) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process zero-length plaintext");
            logOpenSSLError("EVP_CipherUpdate(zero-length)");
            logFunctionExit(functionName);
            return -1;
        }

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL Processed zero-length plaintext");
        }
#endif
        // For CCM with zero-length plaintext, skip EVP_CipherFinal_ex (not
        // supported by CCM mode) and proceed directly to tag retrieval.
        totalOutLen += outLen;
    }

    // Finalize cipher for non-zero input (EVP_CipherFinal_ex is not supported for zero-length CCM)
    if (inputLen > 0) {
        finalLen = 0;

        if (EVP_CipherFinal_ex(
                ctx, (unsigned char*)(outputBytes + outputOffset + totalOutLen),
                &finalLen) != 1) {
            (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                                  "Failed to finalize CCM cipher");
            logOpenSSLError("EVP_CipherFinal_ex");
            logFunctionExit(functionName);
            return -1;
        }

        totalOutLen += finalLen;
    }

    // Get the tag and append it to the output
    totalOutLen =
        getAndAppendTag(env, ctx, outputBytes, outputOffset, totalOutLen,
                        tagLen, EVP_CTRL_CCM_GET_TAG, functionName);
    if (totalOutLen < 0) {
        cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
        return -1;
    }

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM encrypt final complete, total output: %d "
            "bytes",
            totalOutLen);
    }
#endif

    logFunctionExit(functionName);

    return totalOutLen;
}

//============================================================================
// CCM_decryptFinal - Finalize CCM decryption and verify authentication tag
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.CCM_decryptFinal";
    CipherContext*     cipherCtx    = NULL;
    EVP_CIPHER_CTX*    ctx;
    int                totalOutLen = 0;
    int                actualInputLen;
    int                outLen;
    jbyte*             outputBytes;
    jbyte*             inputBytes;
    int                finalLen;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    /* Verify tagLen matches the value fixed at CCM_init time.
     * OpenSSL's internal CBC-MAC expects the same tag length for verification
     * as was registered via EVP_CTRL_CCM_SET_TAG at init time. */
    if (tagLen != cipherCtx->tagLen) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "CCM tagLen mismatch: decryptFinal tagLen differs from CCM_init tagLen");
        logFunctionExit(functionName);
        return -1;
    }

    ctx = cipherCtx->ctx;

    // Calculate actual ciphertext length (input - tag)
    actualInputLen = inputLen - tagLen;

    if (actualInputLen < 0) {
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Input length less than tag length");
        logFunctionExit(functionName);
        return -1;
    }

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM_decryptFinal: inputLen=%d, "
            "actualInputLen=%d, tagLen=%d",
            inputLen, actualInputLen, tagLen);
    }
#endif

    // For CCM, set plaintext length before processing AAD
    outLen = 0;

    if (EVP_CipherUpdate(ctx, NULL, &outLen, NULL, actualInputLen) != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to set CCM plaintext length");
        logOpenSSLError("EVP_CipherUpdate(set plaintext length)");
        logFunctionExit(functionName);
        return -1;
    }

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM OpenSSL Set CCM plaintext length: %d bytes",
                     actualInputLen);
    }
#endif

    // Process AAD if present
    if (!processAADFromArray(env, ctx, aad, aadLen, functionName)) {
        return -1;
    }

    // Validate output buffer size (plaintext only).
    // Use validateOutputBuffer() to avoid jint overflow in the addition
    // outputOffset + actualInputLen (same fix applied to CCM_encryptFinal).
    if (!validateOutputBuffer(env, output, outputOffset, actualInputLen,
                              functionName,
                              "Output buffer too small or invalid offset")) {
        logFunctionExit(functionName);
        return -1;
    }

    outputBytes = getByteArrayElementsSafe(env, output, functionName, "output");
    if (outputBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        logFunctionExit(functionName);
        return -1;
    }

    /* Validate inputOffset before extractAndSetTag and the ciphertext update —
     * both use inputOffset in pointer arithmetic against the pinned array. */
    if (input != NULL && inputLen > 0) {
        jsize inputArrayLen = (*env)->GetArrayLength(env, input);
        if (!validateOffsetAndLength(env, inputArrayLen, inputOffset, inputLen,
                                     functionName, "input")) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            logFunctionExit(functionName);
            return -1;
        }
    }

    // Extract and set the tag for verification
    if (!extractAndSetTag(env, ctx, input, inputOffset, inputLen, tagLen,
                          EVP_CTRL_CCM_SET_TAG, functionName)) {
        cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
        return -1;
    }

    // Process ciphertext if present
    if (actualInputLen > 0) {
        inputBytes =
            getByteArrayElementsSafe(env, input, functionName, "input");
        if (inputBytes == NULL) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                                  "Failed to get input bytes");
            logFunctionExit(functionName);
            return -1;
        }

        outLen = 0;

        if (EVP_CipherUpdate(ctx, (unsigned char*)(outputBytes + outputOffset),
                             &outLen,
                             (unsigned char*)(inputBytes + inputOffset),
                             actualInputLen) != 1) {
            cleanupIOArrays(env, input, inputBytes, output, outputBytes,
                            JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to process final input");
            logOpenSSLError("EVP_CipherUpdate");
            logFunctionExit(functionName);
            return -1;
        }

        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
        totalOutLen += outLen;

#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_CCM OpenSSL Processed %d bytes of final input, output "
                "%d bytes",
                actualInputLen, outLen);
        }
#endif
    } else {
        // For zero-length ciphertext
        if (!processZeroLengthInput(env, ctx, outputBytes, outputOffset,
                                    functionName)) {
            cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
            return -1;
        }
    }

    // Finalize cipher (verifies authentication tag)
    finalLen = 0;

    if (EVP_CipherFinal_ex(
            ctx, (unsigned char*)(outputBytes + outputOffset + totalOutLen),
            &finalLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_TAG_MISMATCH,
                              "CCM tag verification failed");
#ifdef DEBUG_CCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_CCM OpenSSL CCM tag verification failed");
        }
#endif
        logFunctionExit(functionName);
        return OPENSSL_TAG_MISMATCH_ERROR;
    }

    totalOutLen += finalLen;

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CCM OpenSSL CCM decrypt final complete, total output: %d "
            "bytes",
            totalOutLen);
    }
#endif

    logFunctionExit(functionName);

    return totalOutLen;
}
