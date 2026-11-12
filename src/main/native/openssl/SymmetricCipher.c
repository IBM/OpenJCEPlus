/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"

/* Internal cipher context - opaque handle exchanged as jlong with Java. */
typedef struct {
    EVP_CIPHER_CTX *ctx;        /* OpenSSL cipher context                    */
    EVP_CIPHER     *cipher;     /* Fetched cipher (EVP_CIPHER_fetch)          */
    int             blockSize;  /* Cipher block size in bytes                */
    unsigned char  *iv;         /* IV given to CIPHER_init (for needsReinit) */
    int             ivLen;      /* IV length in bytes                        */
} CipherContext;

/*
 * Resets ctx to its post-init state when Java passes needsReinit.
 * The key schedule, direction and padding already live in ctx, so only the
 * IV (which the previous operation advanced) is passed again; no key copy
 * is kept. enc == -1 keeps the current direction.
 * Returns 1 on success, 0 on failure (exception already thrown).
 */
static int reinitCipher(JNIEnv *env, CipherContext *cipherCtx) {
    if (EVP_CipherInit_ex(cipherCtx->ctx, NULL, NULL, NULL, cipherCtx->iv,
                          -1) != 1) {
        throwOSSLException(env, 0,
                           "SymmetricCipher: reinit failed");
        osslCheckStatus();
        return 0;
    }
    return 1;
}

/*
 * Checks that arr[off .. off+required) lies inside arr. A NULL array is
 * accepted only when required == 0.
 * Returns 1 if valid, 0 otherwise (exception already thrown).
 */
static int checkRange(JNIEnv *env, jbyteArray arr, jint off, jlong required,
                      const char *msg) {
    jsize total;

    if (off < 0 || required < 0) {
        throwOSSLException(env, 0, msg);
        return 0;
    }
    if (arr == NULL) {
        if (required == 0) {
            return 1;
        }
        throwOSSLException(env, 0, msg);
        return 0;
    }
    total = (*env)->GetArrayLength(env, arr);
    if (off > total || (jlong)total - off < required) {
        throwOSSLException(env, 0, msg);
        return 0;
    }
    return 1;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1create(
    JNIEnv *env, jclass cls, jlong osslContextId, jstring cipherName)
{
    const char    *cipherNameChars = NULL;
    CipherContext *cipherCtx       = NULL;
    jlong          retCipher       = 0;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherName == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_create: cipherName is null");
        goto cleanup;
    }

    cipherNameChars = getStringUTFCharsSafe(env, cipherName,
                                            "CIPHER_create: GetStringUTFChars failed");
    if (cipherNameChars == NULL) {
        goto cleanup;
    }

    if (debug) {
        gslogMessage("CIPHER_create: cipher=%s", cipherNameChars);
    }

    cipherCtx = (CipherContext *)mallocSafe(env, sizeof(CipherContext),
                                            "CIPHER_create: malloc CipherContext failed");
    if (cipherCtx == NULL) {
        goto cleanup;
    }

    /* mallocSafe zeroes the block; set fields explicitly for clarity */
    cipherCtx->cipher    = NULL;
    cipherCtx->ctx       = NULL;
    cipherCtx->blockSize = 0;
    cipherCtx->iv        = NULL;
    cipherCtx->ivLen     = 0;

    cipherCtx->cipher = EVP_CIPHER_fetch(NULL, cipherNameChars, NULL);
    if (cipherCtx->cipher == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_create: EVP_CIPHER_fetch failed");
        osslCheckStatus();
        goto cleanup;
    }

    cipherCtx->ctx = EVP_CIPHER_CTX_new();
    if (cipherCtx->ctx == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_create: EVP_CIPHER_CTX_new failed");
        osslCheckStatus();
        goto cleanup;
    }

    retCipher = (jlong)((intptr_t)cipherCtx);

cleanup:
    releaseStringUTFChars(env, cipherName, cipherNameChars);
    if (retCipher == 0 && cipherCtx != NULL) {
        if (cipherCtx->ctx    != NULL) EVP_CIPHER_CTX_free(cipherCtx->ctx);
        if (cipherCtx->cipher != NULL) EVP_CIPHER_free(cipherCtx->cipher);
        free(cipherCtx);
    }
    return retCipher;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_init
 * Signature: (JJII[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1init(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId,
    jint isEncrypt, jint paddingId, jbyteArray key, jbyteArray iv)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);
    unsigned char *keyNative = NULL;
    jsize          keyLen    = 0;
    jsize          ivLen     = 0;
    int            expectedIvLen = 0;
    int            rc        = 0;
    int            evpCalled = 0; /* 1 once EVP_*Init_ex has been attempted */

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || key == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_init: null context or key");
        goto cleanup;
    }

    keyLen = (*env)->GetArrayLength(env, key);
    if (iv != NULL) {
        ivLen = (*env)->GetArrayLength(env, iv);
    }

    /* A mode that needs an IV must not silently run with OpenSSL's zero IV */
    expectedIvLen = EVP_CIPHER_get_iv_length(cipherCtx->cipher);
    if (expectedIvLen > 0 && (iv == NULL || ivLen < expectedIvLen)) {
        throwOSSLException(env, 0,
                           "CIPHER_init: missing or too short IV");
        goto cleanup;
    }

    cipherCtx->blockSize = EVP_CIPHER_get_block_size(cipherCtx->cipher);

    /*
     * Copy the key into a temporary native buffer that is cleansed on every
     * path; it is not kept after EVP_*Init_ex. The IV is kept for
     * needsReinit. The Java arrays are never modified.
     */
    keyNative = (unsigned char *)mallocSafe(env, (size_t)keyLen,
                                            "CIPHER_init: malloc key failed");
    if (keyNative == NULL) {
        goto cleanup;
    }
    (*env)->GetByteArrayRegion(env, key, 0, keyLen, (jbyte *)keyNative);
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    if (cipherCtx->iv != NULL) {
        OPENSSL_cleanse(cipherCtx->iv, (size_t)cipherCtx->ivLen);
        free(cipherCtx->iv);
        cipherCtx->iv = NULL;
    }
    cipherCtx->ivLen = 0;
    if (iv != NULL && ivLen > 0) {
        cipherCtx->iv = (unsigned char *)mallocSafe(env, (size_t)ivLen,
                                                    "CIPHER_init: malloc iv failed");
        if (cipherCtx->iv == NULL) {
            goto cleanup;
        }
        cipherCtx->ivLen = (int)ivLen;
        (*env)->GetByteArrayRegion(env, iv, 0, ivLen, (jbyte *)cipherCtx->iv);
        if ((*env)->ExceptionCheck(env)) {
            goto cleanup;
        }
    }

    evpCalled = 1;
    if (isEncrypt) {
        rc = EVP_EncryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                keyNative, cipherCtx->iv);
    } else {
        rc = EVP_DecryptInit_ex(cipherCtx->ctx, cipherCtx->cipher, NULL,
                                keyNative, cipherCtx->iv);
    }

    if (rc == 1) {
        /* EVP_CIPHER_CTX_set_padding must be called after cipher is bound */
        rc = EVP_CIPHER_CTX_set_padding(cipherCtx->ctx,
                                        (cipherCtx->blockSize == 1) ? 0
                                                                    : (paddingId != 0));
    }

cleanup:
    if (keyNative != NULL) {
        OPENSSL_cleanse(keyNative, (size_t)keyLen);
        free(keyNative);
    }
    if (evpCalled && rc != 1) {
        throwOSSLException(env, 0,
                           "CIPHER_init: EVP_*Init_ex failed");
        osslCheckStatus();
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_clean
 * Signature: (JJ)V
 *
 * Resets the EVP_CIPHER_CTX state without freeing the CipherContext struct.
 * Called by the Java layer to reset mid-stream state.
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1clean(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)cls;
    (void)osslContextId;

    if (cipherCtx == NULL) {
        return;
    }

    if (cipherCtx->ctx != NULL) {
        if (EVP_CIPHER_CTX_reset(cipherCtx->ctx) != 1) {
            throwOSSLException(env, 0,
                               "CIPHER_clean: EVP_CIPHER_CTX_reset failed");
            osslCheckStatus();
        }
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_setPadding
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1setPadding(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId, jint paddingId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)cls;
    (void)osslContextId;

    if (cipherCtx == NULL || cipherCtx->ctx == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_setPadding: null context");
        return;
    }

    if (EVP_CIPHER_CTX_set_padding(cipherCtx->ctx,
                                   (cipherCtx->blockSize == 1) ? 0
                                                               : (paddingId != 0)) != 1) {
        throwOSSLException(env, 0,
                           "CIPHER_setPadding: EVP_CIPHER_CTX_set_padding failed");
        osslCheckStatus();
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_getBlockSize
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getBlockSize(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)env;
    (void)cls;
    (void)osslContextId;

    if (cipherCtx != NULL && cipherCtx->cipher != NULL) {
        return (jint)EVP_CIPHER_get_block_size(cipherCtx->cipher);
    }
    return 0;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_getKeyLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getKeyLength(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)env;
    (void)cls;
    (void)osslContextId;

    if (cipherCtx != NULL && cipherCtx->cipher != NULL) {
        return (jint)EVP_CIPHER_get_key_length(cipherCtx->cipher);
    }
    return 0;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_getIVLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getIVLength(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)env;
    (void)cls;
    (void)osslContextId;

    if (cipherCtx != NULL && cipherCtx->cipher != NULL) {
        return (jint)EVP_CIPHER_get_iv_length(cipherCtx->cipher);
    }
    return 0;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_getOID
 * Signature: (JJ)I
 *
 * Returns the NID for the cipher, matching the OCK backend convention.
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getOID(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)env;
    (void)cls;
    (void)osslContextId;

    if (cipherCtx != NULL && cipherCtx->cipher != NULL) {
        return (jint)EVP_CIPHER_get_type(cipherCtx->cipher);
    }
    return 0;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_encryptUpdate
 * Signature: (JJ[BII[BIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1encryptUpdate(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId,
    jbyteArray plaintext, jint plaintextOffset, jint plaintextLen,
    jbyteArray ciphertext, jint ciphertextOffset, jboolean needsReinit)
{
    CipherContext *cipherCtx        = (CipherContext *)((intptr_t)cipherId);
    jbyte         *plaintextNative  = NULL;
    jbyte         *ciphertextNative = NULL;
    int            outLen           = 0;
    int            returnResult     = FAIL_CIPHER_INTERNAL_ENCRYPTUPDATE;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || plaintext == NULL || ciphertext == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_encryptUpdate: null argument");
        goto cleanup;
    }

    /*
     * EVP_EncryptUpdate may write up to buffered + inputLen bytes, i.e.
     * inputLen + blockSize - 1 once the buffered partial block is included.
     */
    if (!checkRange(env, plaintext, plaintextOffset, plaintextLen,
                    "CIPHER_encryptUpdate: invalid input range") ||
        !checkRange(env, ciphertext, ciphertextOffset,
                    (jlong)plaintextLen + EVP_CIPHER_get_block_size(cipherCtx->cipher),
                    "CIPHER_encryptUpdate: output buffer too small")) {
        goto cleanup;
    }

    if (needsReinit) {
        if (!reinitCipher(env, cipherCtx)) {
            goto cleanup;
        }
    }

    plaintextNative = getByteArrayElementsSafe(env, plaintext,
                          "CIPHER_encryptUpdate: GetByteArrayElements plaintext failed");
    if (plaintextNative == NULL) {
        goto cleanup;
    }

    ciphertextNative = getByteArrayElementsSafe(env, ciphertext,
                           "CIPHER_encryptUpdate: GetByteArrayElements ciphertext failed");
    if (ciphertextNative == NULL) {
        goto cleanup;
    }

    if (EVP_EncryptUpdate(cipherCtx->ctx,
                          (unsigned char *)(ciphertextNative + ciphertextOffset),
                          &outLen,
                          (unsigned char *)(plaintextNative  + plaintextOffset),
                          (int)plaintextLen) != 1) {
        throwOSSLException(env, 0,
                           "CIPHER_encryptUpdate: EVP_EncryptUpdate failed");
        osslCheckStatus();
        goto cleanup;
    }

    returnResult = outLen;

cleanup:
    if (plaintextNative  != NULL) {
        releaseByteArrayElements(env, plaintext,  plaintextNative,  JNI_ABORT);
    }
    if (ciphertextNative != NULL) {
        releaseByteArrayElements(env, ciphertext, ciphertextNative,
                                 (returnResult >= 0) ? 0 : JNI_ABORT);
    }
    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_decryptUpdate
 * Signature: (JJ[BII[BIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1decryptUpdate(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId,
    jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen,
    jbyteArray plaintext, jint plaintextOffset, jboolean needsReinit)
{
    CipherContext *cipherCtx        = (CipherContext *)((intptr_t)cipherId);
    jbyte         *ciphertextNative = NULL;
    jbyte         *plaintextNative  = NULL;
    int            outLen           = 0;
    int            returnResult     = FAIL_CIPHER_INTERNAL_DECRYPTUPDATE;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || ciphertext == NULL || plaintext == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_decryptUpdate: null argument");
        goto cleanup;
    }

    /* EVP_DecryptUpdate may write up to inputLen + blockSize bytes */
    if (!checkRange(env, ciphertext, ciphertextOffset, ciphertextLen,
                    "CIPHER_decryptUpdate: invalid input range") ||
        !checkRange(env, plaintext, plaintextOffset,
                    (jlong)ciphertextLen + EVP_CIPHER_get_block_size(cipherCtx->cipher),
                    "CIPHER_decryptUpdate: output buffer too small")) {
        goto cleanup;
    }

    if (needsReinit) {
        if (!reinitCipher(env, cipherCtx)) {
            goto cleanup;
        }
    }

    ciphertextNative = getByteArrayElementsSafe(env, ciphertext,
                           "CIPHER_decryptUpdate: GetByteArrayElements ciphertext failed");
    if (ciphertextNative == NULL) {
        goto cleanup;
    }

    plaintextNative = getByteArrayElementsSafe(env, plaintext,
                          "CIPHER_decryptUpdate: GetByteArrayElements plaintext failed");
    if (plaintextNative == NULL) {
        goto cleanup;
    }

    if (EVP_DecryptUpdate(cipherCtx->ctx,
                          (unsigned char *)(plaintextNative  + plaintextOffset),
                          &outLen,
                          (unsigned char *)(ciphertextNative + ciphertextOffset),
                          (int)ciphertextLen) != 1) {
        throwOSSLException(env, 0,
                           "CIPHER_decryptUpdate: EVP_DecryptUpdate failed");
        osslCheckStatus();
        goto cleanup;
    }

    returnResult = outLen;

cleanup:
    if (ciphertextNative != NULL) {
        releaseByteArrayElements(env, ciphertext, ciphertextNative, JNI_ABORT);
    }
    if (plaintextNative  != NULL) {
        releaseByteArrayElements(env, plaintext,  plaintextNative,
                                 (returnResult >= 0) ? 0 : JNI_ABORT);
    }
    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_encryptFinal
 * Signature: (JJ[BII[BIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1encryptFinal(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId,
    jbyteArray plaintext, jint plaintextOffset, jint plaintextLen,
    jbyteArray ciphertext, jint ciphertextOffset, jboolean needsReinit)
{
    CipherContext *cipherCtx        = (CipherContext *)((intptr_t)cipherId);
    jbyte         *plaintextNative  = NULL;
    jbyte         *ciphertextNative = NULL;
    int            updateOutLen     = 0;
    int            finalOutLen      = 0;
    int            returnResult     = FAIL_CIPHER_INTERNAL_ENCRYPTFINAL;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || ciphertext == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_encryptFinal: null argument");
        goto cleanup;
    }

    /*
     * Update + final with PKCS padding may write up to
     * buffered + inputLen + blockSize bytes, i.e. inputLen + 2*blockSize - 1.
     */
    if (!checkRange(env, plaintext, plaintextOffset, plaintextLen,
                    "CIPHER_encryptFinal: invalid input range") ||
        !checkRange(env, ciphertext, ciphertextOffset,
                    (jlong)plaintextLen + 2 * (jlong)EVP_CIPHER_get_block_size(cipherCtx->cipher) - 1,
                    "CIPHER_encryptFinal: output buffer too small")) {
        goto cleanup;
    }

    if (needsReinit) {
        if (!reinitCipher(env, cipherCtx)) {
            goto cleanup;
        }
    }

    if (plaintextLen > 0) {
        plaintextNative = getByteArrayElementsSafe(env, plaintext,
                              "CIPHER_encryptFinal: GetByteArrayElements plaintext failed");
        if (plaintextNative == NULL) {
            goto cleanup;
        }
    }

    ciphertextNative = getByteArrayElementsSafe(env, ciphertext,
                           "CIPHER_encryptFinal: GetByteArrayElements ciphertext failed");
    if (ciphertextNative == NULL) {
        goto cleanup;
    }

    if (plaintextLen > 0) {
        if (EVP_EncryptUpdate(cipherCtx->ctx,
                              (unsigned char *)(ciphertextNative + ciphertextOffset),
                              &updateOutLen,
                              (unsigned char *)(plaintextNative  + plaintextOffset),
                              (int)plaintextLen) != 1) {
            throwOSSLException(env, 0,
                               "CIPHER_encryptFinal: EVP_EncryptUpdate failed");
            osslCheckStatus();
            goto cleanup;
        }
    }

    if (EVP_EncryptFinal_ex(cipherCtx->ctx,
                            (unsigned char *)(ciphertextNative + ciphertextOffset
                                              + updateOutLen),
                            &finalOutLen) != 1) {
        throwOSSLException(env, 0,
                           "CIPHER_encryptFinal: EVP_EncryptFinal_ex failed");
        osslCheckStatus();
        goto cleanup;
    }

    returnResult = updateOutLen + finalOutLen;

cleanup:
    if (plaintextNative  != NULL) {
        releaseByteArrayElements(env, plaintext,  plaintextNative,  JNI_ABORT);
    }
    if (ciphertextNative != NULL) {
        releaseByteArrayElements(env, ciphertext, ciphertextNative,
                                 (returnResult >= 0) ? 0 : JNI_ABORT);
    }
    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_decryptFinal
 * Signature: (JJ[BII[BIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1decryptFinal(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId,
    jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen,
    jbyteArray plaintext, jint plaintextOffset, jboolean needsReinit)
{
    CipherContext *cipherCtx        = (CipherContext *)((intptr_t)cipherId);
    jbyte         *ciphertextNative = NULL;
    jbyte         *plaintextNative  = NULL;
    int            updateOutLen     = 0;
    int            finalOutLen      = 0;
    int            returnResult     = FAIL_CIPHER_INTERNAL_DECRYPTFINAL;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (cipherCtx == NULL || plaintext == NULL) {
        throwOSSLException(env, 0,
                           "CIPHER_decryptFinal: null argument");
        goto cleanup;
    }

    /* Buffered data held in the EVP context can add up to one block */
    if (!checkRange(env, ciphertext, ciphertextOffset, ciphertextLen,
                    "CIPHER_decryptFinal: invalid input range") ||
        !checkRange(env, plaintext, plaintextOffset,
                    (jlong)ciphertextLen + EVP_CIPHER_get_block_size(cipherCtx->cipher),
                    "CIPHER_decryptFinal: output buffer too small")) {
        goto cleanup;
    }

    if (needsReinit) {
        if (!reinitCipher(env, cipherCtx)) {
            goto cleanup;
        }
    }

    if (ciphertextLen > 0) {
        ciphertextNative = getByteArrayElementsSafe(env, ciphertext,
                               "CIPHER_decryptFinal: GetByteArrayElements ciphertext failed");
        if (ciphertextNative == NULL) {
            goto cleanup;
        }
    }

    plaintextNative = getByteArrayElementsSafe(env, plaintext,
                          "CIPHER_decryptFinal: GetByteArrayElements plaintext failed");
    if (plaintextNative == NULL) {
        goto cleanup;
    }

    if (ciphertextLen > 0) {
        if (EVP_DecryptUpdate(cipherCtx->ctx,
                              (unsigned char *)(plaintextNative  + plaintextOffset),
                              &updateOutLen,
                              (unsigned char *)(ciphertextNative + ciphertextOffset),
                              (int)ciphertextLen) != 1) {
            throwOSSLException(env, 0,
                               "CIPHER_decryptFinal: EVP_DecryptUpdate failed");
            osslCheckStatus();
            goto cleanup;
        }
    }

    /* Clear stale errors so the reason check below reflects this call only */
    ERR_clear_error();
    if (EVP_DecryptFinal_ex(cipherCtx->ctx,
                            (unsigned char *)(plaintextNative + plaintextOffset
                                              + updateOutLen),
                            &finalOutLen) != 1) {
        unsigned long errCode = ERR_peek_error();
        if ((ERR_GET_LIB(errCode) == ERR_LIB_EVP ||
             ERR_GET_LIB(errCode) == ERR_LIB_PROV) &&
            ERR_GET_REASON(errCode) == EVP_R_BAD_DECRYPT) {
            ERR_clear_error();
            returnResult = FAIL_CIPHER_INTERNAL_DECRYPTFINAL_BAD_PADDING_ERROR;
        } else {
            throwOSSLException(env, 0,
                               "CIPHER_decryptFinal: EVP_DecryptFinal_ex failed");
            osslCheckStatus();
        }
        goto cleanup;
    }

    returnResult = updateOutLen + finalOutLen;

cleanup:
    if (ciphertextNative != NULL) {
        releaseByteArrayElements(env, ciphertext, ciphertextNative, JNI_ABORT);
    }
    if (plaintextNative  != NULL) {
        releaseByteArrayElements(env, plaintext,  plaintextNative,
                                 (returnResult >= 0) ? 0 : JNI_ABORT);
    }
    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1delete(
    JNIEnv *env, jclass cls, jlong osslContextId, jlong cipherId)
{
    CipherContext *cipherCtx = (CipherContext *)((intptr_t)cipherId);

    (void)env;
    (void)cls;
    (void)osslContextId;

    if (cipherCtx == NULL) {
        return;
    }

    if (cipherCtx->iv != NULL) {
        OPENSSL_cleanse(cipherCtx->iv, (size_t)cipherCtx->ivLen);
        free(cipherCtx->iv);
        cipherCtx->iv = NULL;
    }
    if (cipherCtx->ctx != NULL) {
        EVP_CIPHER_CTX_free(cipherCtx->ctx);
        cipherCtx->ctx = NULL;
    }
    if (cipherCtx->cipher != NULL) {
        EVP_CIPHER_free(cipherCtx->cipher);
        cipherCtx->cipher = NULL;
    }
    free(cipherCtx);
}
