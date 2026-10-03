/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLSymmetricCipher.c
 * @brief Implementation of symmetric cipher operations using OpenSSL.
 *
 * This file implements symmetric encryption and decryption for various
 * algorithms and modes using OpenSSL's EVP interface. Supports:
 * - Block ciphers: AES, DES, Triple DES
 * - Stream ciphers: ChaCha20
 * - Modes: ECB, CBC, CTR, OFB, CFB, and others
 * - Padding: PKCS#5/PKCS#7 padding support
 * - Context reuse: Efficient reinitialization for multiple operations
 *
 * The implementation provides streaming operations (update/final pattern)
 * for processing data in chunks, which is essential for large files and
 * memory-constrained environments.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "OpenSSLSymmetricCipher.h"
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

//============================================================================
// CIPHER_create - Create a new cipher context
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1create(
    JNIEnv* env, jclass cls, jlong osslContextId, jstring cipherName) {
    static const char* functionName =
        "NativeOpenSSLImplementation.CIPHER_create";

    logFunctionEntry(functionName);

    // Validate and get context
    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, &context)) {
        logFunctionExit(functionName);
        return -1;
    }

    const char* name =
        getStringUTFCharsSafe(env, cipherName, functionName, "cipher name");
    if (name == NULL) {
        return -1;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Creating cipher with name: %s",
                     name);
        // NOTE: Key material is never logged, even in debug mode, for security
    }
#endif

    CipherContext* cipherCtx = (CipherContext*)mallocSafe(
        env, sizeof(CipherContext),
        "Failed to allocate memory for cipher context");

    if (cipherCtx == NULL) {
        cleanupStringUTFChars(env, cipherName, name);
        logFunctionExit(functionName);
        return -1;
    }

    // Memory already zeroed by mallocSafe
    cipherCtx->key         = NULL;
    cipherCtx->iv          = NULL;
    cipherCtx->blockSize   = 0;
    cipherCtx->tagLen      = 0;
    cipherCtx->updateCount = 0;

    cipherCtx->ctx =
        createCipherCtxSafe(env, functionName, OPENSSL_CIPHER_INIT_FAILED,
                            "Failed to create cipher context");
    if (cipherCtx->ctx == NULL) {
        free(cipherCtx);
        cleanupStringUTFChars(env, cipherName, name);
        return -1;
    }

    cipherCtx->cipher = EVP_CIPHER_fetch(context->libctx, name, NULL);

    if (cipherCtx->cipher == NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
        free(cipherCtx);
        cleanupStringUTFChars(env, cipherName, name);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to fetch cipher");
        logOpenSSLError("EVP_CIPHER_fetch");
        logFunctionExit(functionName);
        return -1;
    }

    cleanupStringUTFChars(env, cipherName, name);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Created cipher context %p",
                     cipherCtx);
    }
#endif

    logFunctionExit(functionName);

    return (jlong)cipherCtx;
}

//============================================================================
// CIPHER_init - Initialize cipher with key and IV
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1init(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jint paddingId, jbyteArray key, jbyteArray iv) {
    static const char* functionName = "OpenSSLNativeInterface.CIPHER_init";
    CipherContext*     cipherCtx    = NULL;
    jbyte*             keyBytes;
    jsize              keyLen;
    jbyte*             ivBytes = NULL;
    jsize              ivLen   = 0;
    int                result;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return;
    }

    cipherCtx->padding   = paddingId;
    cipherCtx->encrypt   = encrypt;
    cipherCtx->blockSize = EVP_CIPHER_get_block_size(cipherCtx->cipher);

    keyBytes = getByteArrayElementsSafe(env, key, functionName, "key");
    if (keyBytes == NULL) {
        logFunctionExit(functionName);
        return;
    }

    keyLen = (*env)->GetArrayLength(env, key);

    if (cipherCtx->key != NULL) {
        memset(cipherCtx->key, 0, cipherCtx->keyLen);
        FREE_AND_NULL(cipherCtx->key);
    }
    cipherCtx->keyLen = keyLen;
    cipherCtx->key    = (unsigned char*)mallocSafe(
        env, keyLen, "Failed to allocate memory for key");

    if (cipherCtx->key == NULL) {
        // Zero the key bytes before cleanup for security
        memset(keyBytes, 0, keyLen);
        cleanupByteArray(env, key, keyBytes, JNI_ABORT);
        logFunctionExit(functionName);
        return;
    }
    memcpy(cipherCtx->key, keyBytes, keyLen);

    if (iv != NULL) {
        ivBytes = getByteArrayElementsSafe(env, iv, functionName, "IV");
        if (ivBytes == NULL) {
            memset(keyBytes, 0, keyLen);
            cleanupByteArray(env, key, keyBytes, JNI_ABORT);
            logFunctionExit(functionName);
            return;
        }
        ivLen = (*env)->GetArrayLength(env, iv);

        if (cipherCtx->iv != NULL) {
            memset(cipherCtx->iv, 0, cipherCtx->ivLen);
            FREE_AND_NULL(cipherCtx->iv);
        }
        cipherCtx->ivLen = ivLen;
        /* C-6: guard against mallocSafe(env, 0, ...) for zero-length IV */
        if (ivLen == 0) {
            cipherCtx->iv = NULL;
        } else {
            cipherCtx->iv = (unsigned char*)mallocSafe(
                env, ivLen, "Failed to allocate memory for IV");
        }

        if (ivLen > 0 && cipherCtx->iv == NULL) {
            memset(keyBytes, 0, keyLen);
            memset(ivBytes, 0, ivLen);
            cleanupByteArrays(env, key, keyBytes, iv, ivBytes);
            logFunctionExit(functionName);
            return;
        }
        if (ivLen > 0) {
            memcpy(cipherCtx->iv, ivBytes, ivLen);
        }
    }

    if (encrypt) {
        result = EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                    (unsigned char*)keyBytes,
                                    ivBytes ? (unsigned char*)ivBytes : NULL);
    } else {
        result = EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                    (unsigned char*)keyBytes,
                                    ivBytes ? (unsigned char*)ivBytes : NULL);
    }

    /* EVP_CIPHER_CTX_set_padding must be called after the cipher is bound
     * to the context (i.e. after EVP_EncryptInit_ex/EVP_DecryptInit_ex). */
    if (result == 1) {
        /* Stream cipher modes have block size of 1 and don't need padding */
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, paddingId != 0);
        }
    }

    /* Zero sensitive material before releasing back to JVM heap */
    memset(keyBytes, 0, keyLen);
    if (ivBytes != NULL) {
        memset(ivBytes, 0, ivLen);
    }
    cleanupByteArrays(env, key, keyBytes, iv, ivBytes);

    if (result != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "Failed to initialize cipher");
        logOpenSSLError("EVP_CipherInit_ex");
        logFunctionExit(functionName);
        return;
    }

    logFunctionExit(functionName);
}

//============================================================================
// CIPHER_getBlockSize - Get cipher block size
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getBlockSize(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_getBlockSize";
    CipherContext* cipherCtx = NULL;
    int            blockSize;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    blockSize = EVP_CIPHER_get_block_size(cipherCtx->cipher);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Cipher block size: %d", blockSize);
    }
#endif

    logFunctionExit(functionName);

    return blockSize;
}

//============================================================================
// CIPHER_getKeyLength - Get cipher key length
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getKeyLength(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_getKeyLength";
    CipherContext* cipherCtx = NULL;
    int            keyLength;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    keyLength = EVP_CIPHER_get_key_length(cipherCtx->cipher);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Cipher key length: %d", keyLength);
    }
#endif

    logFunctionExit(functionName);
    return keyLength;
}

//============================================================================
// CIPHER_getIVLength - Get cipher IV length
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getIVLength(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_getIVLength";
    CipherContext* cipherCtx = NULL;
    int            ivLength;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    ivLength = EVP_CIPHER_get_iv_length(cipherCtx->cipher);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER OpenSSL Cipher IV length: %d", ivLength);
    }
#endif

    logFunctionExit(functionName);
    return ivLength;
}

//============================================================================
// CIPHER_encryptUpdate - Encrypt data (streaming operation)
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1encryptUpdate(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_encryptUpdate";
    CipherContext* cipherCtx = NULL;
    jsize          inputLength;
    jbyte*         inBytes;
    jbyte*         outBytes;
    int            outLen = 0;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (needsReinit) {
        if (EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_EncryptInit_ex");
            logFunctionExit(functionName);
            return -1;
        }
        /* Set padding after init — EVP_CIPHER_CTX_set_padding requires the
         * cipher to already be bound to the context to take effect. */
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
    }

    /* Total length */
    inputLength  = (*env)->GetArrayLength(env, input);

    if (!validateOffsetAndLength(env, inputLength, inputOffset, inputLen,
                                 functionName, "input")) {
        logFunctionExit(functionName);
        return -1;
    }

    /* EVP_EncryptUpdate can produce up to inputLen + blockSize - 1 bytes for
     * block ciphers (AES-CBC/ECB).  Validate the full extent of the write. */
    if (!validateOutputBuffer(env, output, outputOffset,
                              inputLen + cipherCtx->blockSize, functionName,
                              "Output buffer too small for update")) {
        return -1;
    }

    inBytes = getByteArrayElementsSafe(env, input, functionName, "input");
    if (inBytes == NULL) {
        logFunctionExit(functionName);
        return -1;
    }

    outBytes = getByteArrayElementsSafe(env, output, functionName, "output");
    if (outBytes == NULL) {
        cleanupIOArrays(env, input, inBytes, NULL, NULL, JNI_FALSE);
        logFunctionExit(functionName);
        return -1;
    }

    if (EVP_EncryptUpdate(
            cipherCtx->ctx, (unsigned char*)(outBytes + outputOffset), &outLen,
            (unsigned char*)(inBytes + inputOffset), inputLen) != 1) {
        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to update cipher");
        logOpenSSLError("EVP_EncryptUpdate");
        logFunctionExit(functionName);
        return -1;
    }

    cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Encrypted %d bytes, output length: %d",
            inputLen, outLen);
    }
#endif

    logFunctionExit(functionName);
    return outLen;
}

//============================================================================
// CIPHER_decryptUpdate - Decrypt data (streaming operation)
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1decryptUpdate(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_decryptUpdate";
    CipherContext* cipherCtx = NULL;
    jsize inputLength;
    jbyte* inBytes;
    jbyte* outBytes;
    int outLen = 0;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (needsReinit) {
        if (EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_DecryptInit_ex");
            logFunctionExit(functionName);
            return -1;
        }
        /* Set padding after init — EVP_CIPHER_CTX_set_padding requires the
         * cipher to already be bound to the context to take effect. */
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
    }

    inputLength  = (*env)->GetArrayLength(env, input);

    if (!validateOffsetAndLength(env, inputLength, inputOffset, inputLen,
                                 functionName, "input")) {
        logFunctionExit(functionName);
        return -1;
    }

    /* EVP_DecryptUpdate can produce up to inputLen + blockSize - 1 bytes for
     * block ciphers (AES-CBC/ECB).  Validate the full extent of the write. */
    if (!validateOutputBuffer(env, output, outputOffset,
                              inputLen + cipherCtx->blockSize, functionName,
                              "Output buffer too small for update")) {
        return -1;
    }

    inBytes =
        getByteArrayElementsSafe(env, input, functionName, "input");
    if (inBytes == NULL) {
        logFunctionExit(functionName);
        return -1;
    }

    outBytes =
        getByteArrayElementsSafe(env, output, functionName, "output");
    if (outBytes == NULL) {
        cleanupByteArray(env, input, inBytes, JNI_ABORT);
        logFunctionExit(functionName);
        return -1;
    }

    if (EVP_DecryptUpdate(
            cipherCtx->ctx, (unsigned char*)(outBytes + outputOffset), &outLen,
            (unsigned char*)(inBytes + inputOffset), inputLen) != 1) {
        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to update cipher");
        logOpenSSLError("EVP_DecryptUpdate");
        logFunctionExit(functionName);
        return -1;
    }

    cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Decrypted %d bytes, output length: %d",
            inputLen, outLen);
    }
#endif

    logFunctionExit(functionName);
    return outLen;
}

//============================================================================
// CIPHER_encryptFinal - Finalize encryption and apply padding
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1encryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_encryptFinal";
    CipherContext* cipherCtx = NULL;
    int totalOutLen = 0;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (needsReinit) {
        if (EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_EncryptInit_ex");
            logFunctionExit(functionName);
            return -1;
        }
        /* Set padding after init — EVP_CIPHER_CTX_set_padding requires the
         * cipher to already be bound to the context to take effect. */
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
    }

    /* Validate that the output buffer can hold inputLen + up to one full block
     * of padding appended by EVP_EncryptFinal_ex.  The plain offset-only check
     * (requiredSize=0) that was here before did not guard the final write. */
    if (!validateOutputBuffer(env, output, outputOffset,
                              inputLen + cipherCtx->blockSize, functionName,
                              "Output buffer too small for ciphertext and padding")) {
        return -1;
    }

    if (input != NULL && inputLen > 0) {
        jsize inputLength = (*env)->GetArrayLength(env, input);

        if (!validateOffsetAndLength(env, inputLength, inputOffset, inputLen,
                                     functionName, "input")) {
            logFunctionExit(functionName);
            return -1;
        }

        jbyte* inBytes =
            getByteArrayElementsSafe(env, input, functionName, "input");
        if (inBytes == NULL) {
            logFunctionExit(functionName);
            return -1;
        }

        jbyte* outBytes =
            getByteArrayElementsSafe(env, output, functionName, "output");
        if (outBytes == NULL) {
            cleanupIOArrays(env, input, inBytes, NULL, NULL, JNI_FALSE);
            logFunctionExit(functionName);
            return -1;
        }

        int outLen = 0;

        if (EVP_EncryptUpdate(cipherCtx->ctx,
                              (unsigned char*)(outBytes + outputOffset),
                              &outLen, (unsigned char*)(inBytes + inputOffset),
                              inputLen) != 1) {
            cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to update cipher");
            logOpenSSLError("EVP_EncryptUpdate");
            logFunctionExit(functionName);
            return -1;
        }

        totalOutLen += outLen;

        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);
    }

    jbyte* outBytes =
        getByteArrayElementsSafe(env, output, functionName, "output");
    if (outBytes == NULL) {
        logFunctionExit(functionName);
        return -1;
    }

    int finalOutLen = 0;

    if (EVP_EncryptFinal_ex(
            cipherCtx->ctx,
            (unsigned char*)(outBytes + outputOffset + totalOutLen),
            &finalOutLen) != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to finalize cipher");
        logOpenSSLError("EVP_EncryptFinal_ex");
        logFunctionExit(functionName);
        return -1;
    }

    totalOutLen += finalOutLen;

    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Finalized encryption, total output length: "
            "%d",
            totalOutLen);
    }
#endif

    logFunctionExit(functionName);

    return totalOutLen;
}

//============================================================================
// CIPHER_decryptFinal - Finalize decryption and remove padding
//============================================================================
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1decryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit) {
    static const char* functionName =
        "OpenSSLNativeInterface.CIPHER_decryptFinal";
    CipherContext* cipherCtx = NULL;
    int totalOutLen = 0;
    jsize inputLength;
    jbyte* inBytes;
    jbyte* outBytes;
    int outLen;
    int finalOutLen;
    int result;
    unsigned long err;

    logFunctionEntry(functionName);

    if (!validateCipherContext(env, (jint)(osslContextId - 1), cipherId, functionName,
                               &cipherCtx)) {
        return -1;
    }

    if (needsReinit) {
        if (EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                               cipherCtx->key, cipherCtx->iv) != 1) {
            setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                                  "Failed to re-initialize cipher for reuse");
            logOpenSSLError("EVP_DecryptInit_ex");
            logFunctionExit(functionName);
            return -1;
        }
        /* Set padding after init — EVP_CIPHER_CTX_set_padding requires the
         * cipher to already be bound to the context to take effect. */
        if (cipherCtx->blockSize == 1) {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, 0);
        } else {
            EVP_CIPHER_CTX_set_padding(cipherCtx->ctx, cipherCtx->padding != 0);
        }
    }

    /* Validate that the output buffer can hold at most inputLen plaintext bytes.
     * (Decryption removes padding, so output <= inputLen.)
     * The plain offset-only check (requiredSize=0) that was here before
     * did not guard the final write at outputOffset + totalOutLen. */
    if (!validateOutputBuffer(env, output, outputOffset, inputLen, functionName,
                              "Output buffer too small for plaintext")) {
        return -1;
    }

    if (input != NULL && inputLen > 0) {
        inputLength = (*env)->GetArrayLength(env, input);

        if (!validateOffsetAndLength(env, inputLength, inputOffset, inputLen,
                                     functionName, "input")) {
            logFunctionExit(functionName);
            return -1;
        }

        inBytes = getByteArrayElementsSafe(env, input, functionName, "input");
        if (inBytes == NULL) {
            logFunctionExit(functionName);
            return -1;
        }

        outBytes =
            getByteArrayElementsSafe(env, output, functionName, "output");
        if (outBytes == NULL) {
            cleanupIOArrays(env, input, inBytes, NULL, NULL, JNI_FALSE);
            logFunctionExit(functionName);
            return -1;
        }

        if (EVP_DecryptUpdate(cipherCtx->ctx,
                              (unsigned char*)(outBytes + outputOffset),
                              &outLen, (unsigned char*)(inBytes + inputOffset),
                              inputLen) != 1) {
            cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_FALSE);
            setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                                  "Failed to update cipher");
            logOpenSSLError("EVP_DecryptUpdate");
            logFunctionExit(functionName);
            return -1;
        }

        totalOutLen += outLen;

        cleanupIOArrays(env, input, inBytes, output, outBytes, JNI_TRUE);
    }

    outBytes = getByteArrayElementsSafe(env, output, functionName, "output");
    if (outBytes == NULL) {
        logFunctionExit(functionName);
        return -1;
    }

    result = EVP_DecryptFinal_ex(
        cipherCtx->ctx, (unsigned char*)(outBytes + outputOffset + totalOutLen),
        &finalOutLen);

    if (result != 1) {
        (*env)->ReleaseByteArrayElements(env, output, outBytes, JNI_ABORT);

        err = ERR_peek_error();

        setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              ERR_GET_REASON(err) == EVP_R_BAD_DECRYPT
                                  ? "Bad padding"
                                  : "Failed to finalize cipher");
        if (ERR_GET_REASON(err) != EVP_R_BAD_DECRYPT) {
            logOpenSSLError("EVP_DecryptFinal_ex");
        }
        logFunctionExit(functionName);
        return -1;
    }

    totalOutLen += finalOutLen;

    (*env)->ReleaseByteArrayElements(env, output, outBytes, 0);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER OpenSSL Finalized decryption, total output length: "
            "%d",
            totalOutLen);
    }
#endif

    logFunctionExit(functionName);

    return totalOutLen;
}

//============================================================================
// CIPHER_delete - Delete cipher context and free resources
//============================================================================
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1delete(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId) {
    static const char* functionName = "OpenSSLNativeInterface.CIPHER_delete";

    logFunctionEntry(functionName);

    /* Cast the opaque jlong back to a pointer.
     * cipherId == 0 means Java passed a null/uninitialized handle — treat
     * as a no-op rather than a crash.  A non-zero value that is not a valid
     * CipherContext* cannot be detected here (same limitation as all other
     * CIPHER_* functions), so callers must not pass stale IDs.
     * Note: CIPHER_delete must NOT call validateCipherContext() because that
     * helper requires ctx != NULL && cipher != NULL, which would block freeing
     * a partially-initialised context and leak its memory. */
    if (cipherId == 0L) {
        logFunctionExit(functionName);
        return;
    }

    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx->key != NULL) {
        memset(cipherCtx->key, 0, cipherCtx->keyLen);
        FREE_AND_NULL(cipherCtx->key);
    }
    if (cipherCtx->iv != NULL) {
        memset(cipherCtx->iv, 0, cipherCtx->ivLen);
        FREE_AND_NULL(cipherCtx->iv);
    }

    if (cipherCtx->cipher != NULL) {
        EVP_CIPHER_free((EVP_CIPHER*)cipherCtx->cipher);
        cipherCtx->cipher = NULL;
    }

    if (cipherCtx->ctx != NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
        cipherCtx->ctx = NULL;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        // Log before free() to avoid use-after-free
        gslogMessage("DETAIL_CIPHER OpenSSL Deleted cipher context %p",
                     cipherCtx);
    }
#endif

    free(cipherCtx);

    logFunctionExit(functionName);
}
