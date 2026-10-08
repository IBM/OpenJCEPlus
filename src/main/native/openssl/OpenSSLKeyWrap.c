/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLKeyWrap.c
 * @brief Implementation of AES Key Wrap algorithms (RFC 3394 and RFC 5649).
 *
 * This file implements AES key wrapping for secure key encryption and
 * transport. Key wrapping provides both confidentiality and integrity
 * protection for cryptographic keys.
 *
 * Supported modes:
 * - RFC 3394: AES Key Wrap (requires plaintext to be multiple of 8 bytes)
 * - RFC 5649: AES Key Wrap with Padding (supports any plaintext length)
 *
 * Key wrapping is commonly used in:
 * - Key management systems
 * - Secure key storage
 * - Key transport protocols (TLS, IPsec, etc.)
 * - Hardware security modules (HSMs)
 *
 * The implementation uses OpenSSL's EVP interface with AES-WRAP cipher modes.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

/* Constants for key wrap operations */
static const int AES_BLOCK_SIZE = 16; /* AES block size for buffer padding */
static const int BITS_PER_BYTE  = 8; /* Bits per byte for key size conversion */

static void cleanupWrapResources(JNIEnv* env, EVP_CIPHER_CTX* ctx,
                                 const EVP_CIPHER* cipher,
                                 unsigned char* outputNative, jbyteArray kek,
                                 unsigned char* kekNative,
                                 jbyteArray     inputArray,
                                 unsigned char* inputNative) {
    if (outputNative != NULL) {
        free(outputNative);
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
    if (cipher != NULL) {
        EVP_CIPHER_free((EVP_CIPHER*)cipher);
    }

    cleanupIOArrays(env, inputArray, (jbyte*)inputNative, kek,
                    (jbyte*)kekNative, JNI_FALSE);
}

static const EVP_CIPHER* getKeyWrapCipher(OSSL_LIB_CTX* libctx, int keyBits,
                                          jboolean padding) {
    const char* cipherName = NULL;

    if (padding) {
        // RFC 5649: AES Key Wrap with Padding
        switch (keyBits) {
            case 128:
                cipherName = "id-aes128-wrap-pad";
                break;
            case 192:
                cipherName = "id-aes192-wrap-pad";
                break;
            case 256:
                cipherName = "id-aes256-wrap-pad";
                break;
            default:
                return NULL;
        }
    } else {
        // RFC 3394: AES Key Wrap
        switch (keyBits) {
            case 128:
                cipherName = "id-aes128-wrap";
                break;
            case 192:
                cipherName = "id-aes192-wrap";
                break;
            case 256:
                cipherName = "id-aes256-wrap";
                break;
            default:
                return NULL;
        }
    }

    return EVP_CIPHER_fetch(libctx, cipherName, NULL);
}

//============================================================================
// KEYWRAP_wrap - Wrap (encrypt) key using AES Key Wrap (RFC 3394/5649)
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYWRAP_1wrap(
    JNIEnv* env, jclass thisObj, jlong osslContextId, jbyteArray plaintext,
    jbyteArray kek, jboolean padding) {
    static const char* functionName = "OpenSSLNativeInterface.KEYWRAP_wrap";

    EVP_CIPHER_CTX*   ctx    = NULL;
    const EVP_CIPHER* cipher = NULL;
    OSSL_LIB_CTX*     libctx = NULL;

    unsigned char* plaintextNative = NULL;
    unsigned char* kekNative       = NULL;
    unsigned char* outputNative    = NULL;
    jbyteArray     outputArray     = NULL;

    jsize    plaintextLen = 0;
    jsize    kekLen       = 0;
    int      outputLen    = 0;
    int      finalLen     = 0;
    int      totalLen     = 0;

    logFunctionEntry(functionName);

    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, &context)) {
        logFunctionExit(functionName);
        return NULL;
    }

    libctx = context->libctx;

    plaintextLen = (*env)->GetArrayLength(env, plaintext);
    kekLen       = (*env)->GetArrayLength(env, kek);

    plaintextNative = (unsigned char*)getByteArrayElementsSafe(
        env, plaintext, functionName, "plaintext");
    if (plaintextNative == NULL) {
        logFunctionExit(functionName);
        return NULL;
    }

    kekNative =
        (unsigned char*)getByteArrayElementsSafe(env, kek, functionName, "KEK");
    if (kekNative == NULL) {
        cleanupByteArray(env, plaintext, (jbyte*)plaintextNative, JNI_ABORT);
        logFunctionExit(functionName);
        return NULL;
    }

    int keyBits = kekLen * BITS_PER_BYTE;
    cipher      = getKeyWrapCipher(libctx, keyBits, padding);
    if (cipher == NULL) {
        cleanupWrapResources(env, NULL, NULL, NULL, kek, kekNative, plaintext,
                             plaintextNative);
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Unsupported key size for key wrap");
        logFunctionExit(functionName);
        return NULL;
    }

    ctx = createCipherCtxSafe(env, functionName, OPENSSL_UNSPECIFIED,
                              "EVP_CIPHER_CTX_new failed");
    if (ctx == NULL) {
        cleanupWrapResources(env, NULL, cipher, NULL, kek, kekNative, plaintext,
                             plaintextNative);
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, kekNative, NULL) != 1) {
        cleanupWrapResources(env, ctx, cipher, NULL, kek, kekNative, plaintext,
                             plaintextNative);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "EVP_EncryptInit_ex failed for key wrap");
        logFunctionExit(functionName);
        return NULL;
    }

    int maxOutputLen = plaintextLen + AES_BLOCK_SIZE;
    outputNative =
        (unsigned char*)mallocSafe(env, maxOutputLen, "output buffer");
    if (outputNative == NULL) {
        cleanupWrapResources(env, ctx, cipher, NULL, kek, kekNative, plaintext,
                             plaintextNative);
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_EncryptUpdate(ctx, outputNative, &outputLen, plaintextNative,
                          plaintextLen) != 1) {
        cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                             plaintext, plaintextNative);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "EVP_EncryptUpdate failed for key wrap");
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_EncryptFinal_ex(ctx, outputNative + outputLen, &finalLen) != 1) {
        cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                             plaintext, plaintextNative);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "EVP_EncryptFinal_ex failed for key wrap");
        logFunctionExit(functionName);
        return NULL;
    }

    totalLen = outputLen + finalLen;

    outputArray = newByteArraySafe(env, totalLen, functionName);
    if (outputArray == NULL) {
        cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                             plaintext, plaintextNative);
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, outputArray, 0, totalLen,
                               (jbyte*)outputNative);

    cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                         plaintext, plaintextNative);

    logFunctionExit(functionName);
    return outputArray;
}

//============================================================================
// KEYWRAP_unwrap - Unwrap (decrypt) key using AES Key Wrap (RFC 3394/5649)
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYWRAP_1unwrap(
    JNIEnv* env, jclass thisObj, jlong osslContextId, jbyteArray ciphertext,
    jbyteArray kek, jboolean padding) {
    static const char* functionName = "OpenSSLNativeInterface.KEYWRAP_unwrap";

    EVP_CIPHER_CTX*   ctx    = NULL;
    const EVP_CIPHER* cipher = NULL;
    OSSL_LIB_CTX*     libctx = NULL;

    unsigned char* ciphertextNative = NULL;
    unsigned char* kekNative        = NULL;
    unsigned char* outputNative     = NULL;
    jbyteArray     outputArray      = NULL;

    jsize    ciphertextLen = 0;
    jsize    kekLen        = 0;
    int      outputLen     = 0;
    int      finalLen      = 0;
    int      totalLen      = 0;

    logFunctionEntry(functionName);

    OpenSSLContext* context = NULL;
    if (!validateAndGetContext(env, (jint)(osslContextId - 1), functionName, &context)) {
        logFunctionExit(functionName);
        return NULL;
    }

    libctx = context->libctx;

    ciphertextLen = (*env)->GetArrayLength(env, ciphertext);
    kekLen        = (*env)->GetArrayLength(env, kek);

    ciphertextNative = (unsigned char*)getByteArrayElementsSafe(
        env, ciphertext, functionName, "ciphertext");
    if (ciphertextNative == NULL) {
        logFunctionExit(functionName);
        return NULL;
    }

    kekNative =
        (unsigned char*)getByteArrayElementsSafe(env, kek, functionName, "KEK");
    if (kekNative == NULL) {
        cleanupByteArray(env, ciphertext, (jbyte*)ciphertextNative, JNI_ABORT);
        logFunctionExit(functionName);
        return NULL;
    }

    int keyBits = kekLen * BITS_PER_BYTE;
    cipher      = getKeyWrapCipher(libctx, keyBits, padding);
    if (cipher == NULL) {
        cleanupWrapResources(env, NULL, NULL, NULL, kek, kekNative, ciphertext,
                             ciphertextNative);
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Unsupported key size for key unwrap");
        logFunctionExit(functionName);
        return NULL;
    }

    ctx = createCipherCtxSafe(env, functionName, OPENSSL_UNSPECIFIED,
                              "EVP_CIPHER_CTX_new failed");
    if (ctx == NULL) {
        cleanupWrapResources(env, NULL, cipher, NULL, kek, kekNative,
                             ciphertext, ciphertextNative);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, kekNative, NULL) != 1) {
        cleanupWrapResources(env, ctx, cipher, NULL, kek, kekNative, ciphertext,
                             ciphertextNative);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_INIT_FAILED,
                              "EVP_DecryptInit_ex failed for key unwrap");
        logFunctionExit(functionName);
        return NULL;
    }

    outputNative =
        (unsigned char*)mallocSafe(env, ciphertextLen, "output buffer");
    if (outputNative == NULL) {
        cleanupWrapResources(env, ctx, cipher, NULL, kek, kekNative, ciphertext,
                             ciphertextNative);
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_DecryptUpdate(ctx, outputNative, &outputLen, ciphertextNative,
                          ciphertextLen) != 1) {
        cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                             ciphertext, ciphertextNative);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "EVP_DecryptUpdate failed for key unwrap - "
                              "possibly invalid wrapped key or KEK");
        logFunctionExit(functionName);
        return NULL;
    }

    if (EVP_DecryptFinal_ex(ctx, outputNative + outputLen, &finalLen) != 1) {
        cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                             ciphertext, ciphertextNative);
        setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "EVP_DecryptFinal_ex failed for key unwrap - "
                              "integrity check failed");
        logFunctionExit(functionName);
        return NULL;
    }

    totalLen = outputLen + finalLen;

    outputArray = newByteArraySafe(env, totalLen, functionName);
    if (outputArray == NULL) {
        cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                             ciphertext, ciphertextNative);
        logFunctionExit(functionName);
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, outputArray, 0, totalLen,
                               (jbyte*)outputNative);

    cleanupWrapResources(env, ctx, cipher, outputNative, kek, kekNative,
                         ciphertext, ciphertextNative);

    logFunctionExit(functionName);
    return outputArray;
}

//============================================================================
// CIPHER_KeyWraporUnwrap - unified wrap/unwrap entry point
// type bit 0 set (1) = wrap, clear (0) = unwrap
// type bit 2 set (4) = with padding (RFC 5649), clear = no padding (RFC 3394)
//============================================================================
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1KeyWraporUnwrap(
    JNIEnv* env, jclass thisObj, jlong osslContextId, jbyteArray key,
    jbyteArray KEK, jint type) {
    jboolean padding = (type & 4) ? JNI_TRUE : JNI_FALSE;
    jboolean isWrap  = (type & 1) ? JNI_TRUE : JNI_FALSE;

    if (isWrap) {
        return Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYWRAP_1wrap(
            env, thisObj, osslContextId, key, KEK, padding);
    } else {
        return Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEYWRAP_1unwrap(
            env, thisObj, osslContextId, key, KEK, padding);
    }
}
