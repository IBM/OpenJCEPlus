/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLGCM.c
 * @brief Implementation of GCM (Galois/Counter Mode) authenticated encryption.
 *
 * This file implements AES-GCM mode operations using OpenSSL's EVP interface.
 * GCM mode combines CTR mode encryption with Galois field multiplication for
 * authentication, providing both confidentiality and authenticity.
 *
 * Key features:
 * - Supports AES-128, AES-192, and AES-256
 * - Configurable tag lengths (4-16 bytes)
 * - Flexible IV lengths (1-1024 bytes, 12 bytes recommended)
 * - Additional Authenticated Data (AAD) support
 * - Streaming and single-shot operations
 * - Parallel processing capability
 *
 * GCM is specified in NIST SP 800-38D and is widely used in TLS, IPsec,
 * and other security protocols due to its high performance and strong
 * security properties.
 */

#include <jni.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include "OpenSSLGCM.h"
#include "OpenSSLContext.h"
#include "OpenSSLSymmetricCipher.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLLogging.h"
#include "OpenSSLHelpers.h"

//============================================================================
// GCM_init - Initialize GCM cipher with key, IV, and tag length
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1init(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_init";

    /* Default GCM IV length as recommended by NIST SP 800-38D */
    const int DEFAULT_GCM_IV_LENGTH = 12;

    CipherContext*  cipherCtx = NULL;
    EVP_CIPHER_CTX* ctx;
    jbyte*          keyBytes;
    jbyte*          ivBytes;
    int             ivLen;
    int             encryptFlag;

    logFunctionEntry(functionName);
#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("GCM_init called: cipherId=%lld, encrypt=%d, tagLen=%d",
                     cipherId, encrypt, tagLen);
    }
#endif

    /* Validate tag length */
    if (!validateIntRange(env, tagLen, MIN_GCM_TAG_SIZE, MAX_GCM_TAG_SIZE,
                          functionName,
                          "Invalid GCM tag length: must be 4-16 bytes")) {
        return;
    }

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return;
    }

    ctx = cipherCtx->ctx;

    keyBytes = getByteArrayElementsSafe(env, key, functionName, "key");
    if (keyBytes == NULL) {
        return;
    }

    ivBytes = getByteArrayElementsSafe(env, iv, functionName, "IV");
    if (ivBytes == NULL) {
        cleanupByteArray(env, key, keyBytes, JNI_ABORT);
        return;
    }

    /* Validate IV length */
    if (!validateArrayLength(env, iv, MIN_GCM_IV_SIZE, MAX_GCM_IV_SIZE,
                             functionName,
                             "Invalid GCM IV length: must be 1-1024 bytes")) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        return;
    }

    ivLen = (*env)->GetArrayLength(env, iv);

    encryptFlag = (encrypt != 0) ? 1 : 0;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM_init: mode=%s, ivLen=%d, tagLen=%d",
            encryptFlag ? "encrypt" : "decrypt", ivLen, tagLen);
    }
#endif

    /* Reset context to ensure clean state when reinitializing a cached context */
#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("GCM_init: Resetting context (cipherId=%lld) before initialization", cipherId);
    }
#endif
    if (EVP_CIPHER_CTX_reset(ctx) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to reset GCM cipher context");
        logOpenSSLError("EVP_CIPHER_CTX_reset");
        logFunctionExit(functionName);
        return;
    }
#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("GCM_init: Context reset successful");
    }
#endif

    if (EVP_CipherInit_ex(ctx, cipherCtx->cipher, NULL, NULL, NULL,
                          encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to initialize GCM cipher");
        logOpenSSLError("EVP_CipherInit_ex");
        logFunctionExit(functionName);
        return;
    }

    // Set IV length if not default
    if (ivLen != DEFAULT_GCM_IV_LENGTH) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLen, NULL) !=
            1) {
            cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to set GCM IV length");
            logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_IVLEN)");
            logFunctionExit(functionName);
            return;
        }
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char*)keyBytes,
                          (unsigned char*)ivBytes, encryptFlag) != 1) {
        cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to set GCM key and IV");
        logOpenSSLError("EVP_CipherInit_ex");
        logFunctionExit(functionName);
        return;
    }

    // Store the tag length for validation in GCM_final
    cipherCtx->tagLen = tagLen;

    cleanupByteArrays(env, key, keyBytes, iv, ivBytes);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_GCM OpenSSL GCM cipher initialized successfully");
    }
#endif

    logFunctionExit(functionName);
}

//============================================================================
// GCM_update - Process data and AAD through GCM cipher
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1update(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_update";
    CipherContext*     cipherCtx    = NULL;
    EVP_CIPHER_CTX*    ctx;
    int                outLen;
    jsize              inputLength;
    jbyte*             inputBytes;
    jbyte*             outputBytes;

    logFunctionEntry(functionName);
#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("GCM_update called: cipherId=%lld, encrypt=%d, inputLen=%d, aadLen=%d",
                     cipherId, encrypt, inputLen, aadLen);
    }
#endif

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    ctx = cipherCtx->ctx;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_GCM OpenSSL GCM_update: inputLen=%d, aadLen=%d",
                     inputLen, aadLen);
    }
#endif

    // Process AAD using helper function
    if (!processAADFromArray(env, ctx, aad, aadLen, functionName)) {
        return -1;
    }

    if (input == NULL) {
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "GCM_update: input array must not be null");
        logFunctionExit(functionName);
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

    if (output == NULL) {
        cleanupIOArrays(env, input, inputBytes, NULL, NULL, JNI_FALSE);
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "GCM_update: output array must not be null");
        logFunctionExit(functionName);
        return -1;
    }

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
                              "Failed to update GCM cipher");
        logOpenSSLError("EVP_CipherUpdate");
        logFunctionExit(functionName);
        return -1;
    }

    cleanupIOArrays(env, input, inputBytes, output, outputBytes, JNI_TRUE);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM update: processed %d bytes, output %d "
            "bytes",
            inputLen, outLen);
    }
#endif

    logFunctionExit(functionName);

    return outLen;
}

//============================================================================
// GCM_encryptFinal - Finalize GCM encryption and generate authentication tag
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_encryptFinal";
    CipherContext*     cipherCtx    = NULL;
    EVP_CIPHER_CTX*    ctx;
    int                totalOutLen = 0;
    int                outLen;
    int                requiredOutputSize;
    jbyte*             outputBytes;
    jbyte*             inputBytes;
    int                finalLen;

    logFunctionEntry(functionName);
#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("GCM_encryptFinal called: cipherId=%lld, inputLen=%d, tagLen=%d, aadLen=%d",
                     cipherId, inputLen, tagLen, aadLen);
    }
#endif

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    ctx = cipherCtx->ctx;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM_encryptFinal: inputLen=%d, tagLen=%d",
            inputLen, tagLen);
    }
#endif

    /* Process AAD if present */
    if (!processAADFromArray(env, ctx, aad, aadLen, functionName)) {
        return -1;
    }

    /* Validate output buffer size.
     * Compute in jlong first to catch the jint overflow that occurs when
     * inputLen is close to INT_MAX and tagLen > 0. */
    if ((jlong)inputLen + (jlong)tagLen > (jlong)INT_MAX) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "Output buffer size overflow: inputLen + tagLen exceeds INT_MAX");
        return -1;
    }
    requiredOutputSize = inputLen + tagLen;
    if (!validateOutputBuffer(env, output, outputOffset, requiredOutputSize,
                              functionName,
                              "Output buffer too small or invalid offset")) {
        return -1;
    }

    outputBytes = getByteArrayElementsSafe(env, output, functionName, "output");
    if (outputBytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Failed to get output bytes");
        logFunctionExit(functionName);
        return -1;
    }

    /* Process final input if present */
    if (input != NULL && inputLen > 0) {
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

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_GCM OpenSSL Processed %d bytes of final input, output "
                "%d bytes",
                inputLen, outLen);
        }
#endif
    }

    /* Finalize cipher */
    if (EVP_CipherFinal_ex(
            ctx, (unsigned char*)(outputBytes + outputOffset + totalOutLen),
            &finalLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to finalize GCM cipher");
        logOpenSSLError("EVP_CipherFinal_ex");
        logFunctionExit(functionName);
        return -1;
    }

    totalOutLen += finalLen;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL Finalized cipher, final output: %d bytes, "
            "total: %d bytes",
            finalLen, totalOutLen);
    }
#endif

    /* Get and append authentication tag */
    totalOutLen =
        getAndAppendTag(env, ctx, outputBytes, outputOffset, totalOutLen,
                        tagLen, EVP_CTRL_GCM_GET_TAG, functionName);
    if (totalOutLen < 0) {
        cleanupIOArrays(env, NULL, NULL, output, outputBytes, JNI_FALSE);
        return -1;
    }

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM encryptFinal complete, total output: %d "
            "bytes",
            totalOutLen);
    }
#endif

    logFunctionExit(functionName);
    return totalOutLen;
}

//============================================================================
// GCM_decryptFinal - Finalize GCM decryption and verify authentication tag
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen) {
    static const char* functionName = "OpenSSLNativeInterface.GCM_decryptFinal";
    CipherContext*     cipherCtx    = NULL;
    EVP_CIPHER_CTX*    ctx;
    int                totalOutLen = 0;
    int                outLen;
    int                requiredOutputSize;
    jbyte*             outputBytes;
    jbyte*             inputBytes;
    int                actualInputLen;
    int                finalLen;

    logFunctionEntry(functionName);
#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage("GCM_decryptFinal called: cipherId=%lld, inputLen=%d, tagLen=%d, aadLen=%d",
                     cipherId, inputLen, tagLen, aadLen);
    }
#endif

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    ctx = cipherCtx->ctx;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM_decryptFinal: inputLen=%d, tagLen=%d",
            inputLen, tagLen);
    }
#endif

    /* Process AAD if present */
    if (!processAADFromArray(env, ctx, aad, aadLen, functionName)) {
        return -1;
    }

    /* Reject impossible inputs before computing requiredOutputSize.
     * inputLen < tagLen would make requiredOutputSize negative; validateOutputBuffer
     * would then pass it as a large positive number after jint wrap, allowing a
     * write past the end of the output buffer. */
    if (inputLen < tagLen) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "GCM decrypt: inputLen is less than tagLen");
        logFunctionExit(functionName);
        return -1;
    }

    /* Validate output buffer size (plaintext = ciphertext - tag).
     * Use validateOutputBuffer() to avoid jint overflow in the addition
     * outputOffset + requiredOutputSize (same fix applied to CCM_encryptFinal). */
    requiredOutputSize = inputLen - tagLen;
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

    /* Pin input once to extract tag and process ciphertext in a single pass */
    actualInputLen = inputLen - tagLen;

    if (input != NULL && inputLen >= tagLen) {
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

        /* Set tag for verification (must be done before ciphertext update) */
        unsigned char* tag =
            (unsigned char*)(inputBytes + inputOffset + inputLen - tagLen);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tagLen, tag) != 1) {
            cleanupIOArrays(env, input, inputBytes, output, outputBytes,
                            JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                                   "Failed to set GCM tag");
            logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_TAG)");
            logFunctionExit(functionName);
            return -1;
        }

#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_GCM OpenSSL Set GCM tag for verification, length: %d",
                tagLen);
        }
#endif

        if (actualInputLen > 0) {
            outLen = 0;
            if (EVP_CipherUpdate(ctx,
                                 (unsigned char*)(outputBytes + outputOffset),
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
            totalOutLen += outLen;

#ifdef DEBUG_GCM_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_GCM OpenSSL Processed %d bytes of final input, "
                    "output %d bytes",
                    actualInputLen, outLen);
            }
#endif
        } else {
            /* Zero-length ciphertext: still need a CipherUpdate call so that
             * OpenSSL finalises its internal GCM state before tag verification.
             * This is only needed when no ciphertext bytes were processed. */
            if (!processZeroLengthInput(env, ctx, outputBytes, outputOffset,
                                        functionName)) {
                cleanupIOArrays(env, input, inputBytes, output, outputBytes,
                                JNI_FALSE);
                return -1;
            }
        }

        (*env)->ReleaseByteArrayElements(env, input, inputBytes, JNI_ABORT);
    }

    /* Finalize cipher (verifies authentication tag)
     * For decryption: EVP_DecryptFinal_ex() verifies the tag and returns failure if invalid
     * For encryption: This step is typically a no-op as the tag was already generated
     */
    finalLen = 0;

    if (EVP_CipherFinal_ex(
            ctx, (unsigned char*)(outputBytes + outputOffset + totalOutLen),
            &finalLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outputBytes, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_TAG_MISMATCH,
                              "GCM tag verification failed");
#ifdef DEBUG_GCM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_GCM OpenSSL GCM tag verification failed");
        }
#endif
        logFunctionExit(functionName);
        return OPENSSL_TAG_MISMATCH_ERROR;
    }

    totalOutLen += finalLen;

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL Finalized cipher, final output: %d bytes, "
            "total: %d bytes",
            finalLen, totalOutLen);
    }
#endif

    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

#ifdef DEBUG_GCM_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_GCM OpenSSL GCM decryptFinal complete, total output: %d "
            "bytes",
            totalOutLen);
    }
#endif

    logFunctionExit(functionName);
    return totalOutLen;
}
