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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "ExceptionCodes.h"
#include "Helpers.h"

/* Structure to hold DRBG context */
typedef struct {
    EVP_RAND_CTX *ctx;
    char         *algName;
} DRBG_Context;

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    RAND_generateSeed
 * Signature: (J[B)V
 *
 * Fills the supplied array with random bytes (used for seed generation).
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_RAND_1generateSeed
  (JNIEnv *env, jclass cls, jlong osslContextId, jbyteArray bytes)
{
    jbyte        *bytesNative = NULL;
    jsize         bytesLen    = 0;
    int           rc          = 0;
    unsigned long err         = 0;
    char          errMsg[256];
    char          fullMsg[512];

    if (bytes == NULL) {
        throwNPE(env, "bytes array is null");
        return;
    }

    bytesLen = (*env)->GetArrayLength(env, bytes);
    if (bytesLen <= 0) {
        return;
    }

    bytesNative = getByteArrayElementsSafe(env, bytes,
                                           "Failed to get byte array elements");
    if (bytesNative == NULL) {
        return;
    }

    rc = RAND_bytes((unsigned char *)bytesNative, (int)bytesLen);

    if (rc != 1) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        releaseByteArrayElements(env, bytes, bytesNative, JNI_ABORT);
        snprintf(fullMsg, sizeof(fullMsg),
                 "RAND_generateSeed failed: %s (error code: %lu)", errMsg, err);
        setPendingOpenSSLException(env, OPENSSL_RAND_GENERATE_FAILED, fullMsg);
        return;
    }

    releaseByteArrayElements(env, bytes, bytesNative, 0);
}

/* ============================================================================
 * Extended Random (DRBG) functions
 * ============================================================================ */

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1create
  (JNIEnv *env, jclass cls, jlong osslContextId, jstring algName)
{
    const char   *algNameChars  = NULL;
    const char   *digestName    = NULL;
    const char   *opensslAlg    = "HASH-DRBG";
    EVP_RAND     *rand          = NULL;
    EVP_RAND_CTX *ctx           = NULL;
    DRBG_Context *drbgCtx       = NULL;
    char         *storedAlgName = NULL;
    OSSL_PARAM    params[2];
    unsigned long err = 0;
    char          errMsg[512];
    char          fullMsg[768];

    if (algName == NULL) {
        throwNPE(env, "algName is null");
        return 0;
    }

    algNameChars = getStringUTFCharsSafe(env, algName,
                                         "Failed to get algorithm name");
    if (algNameChars == NULL) {
        return 0;
    }

    /* Map Java algorithm names to OpenSSL EVP digest names.
     * OpenSSL's HASH-DRBG "digest" parameter must be an EVP_MD name;
     * "SHA-256"/"SHA-512" are the canonical aliases recognised by OpenSSL 3.x. */
    if (strcmp(algNameChars, "SHA256") == 0) {
        digestName = "SHA-256";
    } else if (strcmp(algNameChars, "SHA512") == 0) {
        digestName = "SHA-512";
    } else {
        digestName = algNameChars;
    }

    rand = EVP_RAND_fetch(NULL, opensslAlg, NULL);
    if (rand == NULL) {
        releaseStringUTFChars(env, algName, algNameChars);
        snprintf(errMsg, sizeof(errMsg), "Failed to fetch DRBG algorithm: %s",
                 opensslAlg);
        setPendingOpenSSLException(env, OPENSSL_RAND_FETCH_FAILED, errMsg);
        return 0;
    }

    ctx = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);

    if (ctx == NULL) {
        releaseStringUTFChars(env, algName, algNameChars);
        setPendingOpenSSLException(env, OPENSSL_RAND_CTX_NEW_FAILED,
                                   "Failed to create DRBG context");
        return 0;
    }

    /* Instantiate the DRBG with the digest algorithm passed as params.
     * Per OpenSSL 3 EVP_RAND design, instantiation params (including the
     * digest selection) must be passed to EVP_RAND_instantiate, not set
     * via a separate EVP_RAND_CTX_set_params call on an uninstantiated ctx. */
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)digestName, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, params)) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        EVP_RAND_CTX_free(ctx);
        releaseStringUTFChars(env, algName, algNameChars);
        snprintf(fullMsg, sizeof(fullMsg), "Failed to instantiate DRBG: %s",
                 errMsg);
        setPendingOpenSSLException(env, OPENSSL_RAND_INSTANTIATE_FAILED,
                                   fullMsg);
        return 0;
    }

    drbgCtx = (DRBG_Context *)mallocSafe(env, sizeof(DRBG_Context),
                                          "Failed to allocate DRBG context");
    if (drbgCtx == NULL) {
        EVP_RAND_CTX_free(ctx);
        releaseStringUTFChars(env, algName, algNameChars);
        return 0;
    }

    storedAlgName = strdup(algNameChars);
    if (storedAlgName == NULL) {
        free(drbgCtx);
        EVP_RAND_CTX_free(ctx);
        releaseStringUTFChars(env, algName, algNameChars);
        throwOOM(env, "Failed to store algorithm name");
        return 0;
    }

    drbgCtx->ctx     = ctx;
    drbgCtx->algName = storedAlgName;

    releaseStringUTFChars(env, algName, algNameChars);

    return (jlong)(intptr_t)drbgCtx;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_nextBytes
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1nextBytes
  (JNIEnv *env, jclass cls, jlong osslContextId, jlong drbgContextId,
   jbyteArray bytes)
{
    DRBG_Context  *drbgCtx    = (DRBG_Context *)(intptr_t)drbgContextId;
    jbyte         *bytesNative = NULL;
    jsize          bytesLen    = 0;
    unsigned long  err         = 0;
    char           errMsg[256];
    char           fullMsg[512];

    if (drbgCtx == NULL || drbgCtx->ctx == NULL) {
        throwISE(env, "DRBG context is null or invalid");
        return;
    }

    if (bytes == NULL) {
        throwNPE(env, "bytes array is null");
        return;
    }

    bytesLen = (*env)->GetArrayLength(env, bytes);
    if (bytesLen <= 0) {
        return;
    }

    bytesNative = getByteArrayElementsSafe(env, bytes,
                                           "Failed to get byte array elements");
    if (bytesNative == NULL) {
        return;
    }

    if (!EVP_RAND_generate(drbgCtx->ctx, (unsigned char *)bytesNative,
                           (size_t)bytesLen, 0, 0, NULL, 0)) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        releaseByteArrayElements(env, bytes, bytesNative, JNI_ABORT);
        snprintf(fullMsg, sizeof(fullMsg), "EVP_RAND_generate failed: %s",
                 errMsg);
        setPendingOpenSSLException(env, OPENSSL_RAND_GENERATE_FAILED, fullMsg);
        return;
    }

    releaseByteArrayElements(env, bytes, bytesNative, 0);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_setSeed
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1setSeed
  (JNIEnv *env, jclass cls, jlong osslContextId, jlong drbgContextId,
   jbyteArray seed)
{
    DRBG_Context  *drbgCtx   = (DRBG_Context *)(intptr_t)drbgContextId;
    jbyte         *seedNative = NULL;
    jsize          seedLen    = 0;
    unsigned long  err        = 0;
    char           errMsg[256];
    char           fullMsg[512];

    if (drbgCtx == NULL || drbgCtx->ctx == NULL) {
        throwISE(env, "DRBG context is null or invalid");
        return;
    }

    if (seed == NULL) {
        return; /* Silently ignore null seed */
    }

    seedLen = (*env)->GetArrayLength(env, seed);
    if (seedLen <= 0) {
        return;
    }

    seedNative = getByteArrayElementsSafe(env, seed,
                                          "Failed to get seed array elements");
    if (seedNative == NULL) {
        return;
    }

    if (!EVP_RAND_reseed(drbgCtx->ctx, 0, NULL, 0,
                         (const unsigned char *)seedNative, (size_t)seedLen)) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        releaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
        snprintf(fullMsg, sizeof(fullMsg), "EVP_RAND_reseed failed: %s", errMsg);
        setPendingOpenSSLException(env, OPENSSL_RAND_RESEED_FAILED, fullMsg);
        return;
    }

    releaseByteArrayElements(env, seed, seedNative, JNI_ABORT);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1delete
  (JNIEnv *env, jclass cls, jlong osslContextId, jlong drbgContextId)
{
    DRBG_Context *drbgCtx = (DRBG_Context *)(intptr_t)drbgContextId;

    if (drbgCtx == NULL) {
        return;
    }

    if (drbgCtx->ctx != NULL) {
        EVP_RAND_CTX_free(drbgCtx->ctx);
        drbgCtx->ctx = NULL;
    }

    if (drbgCtx->algName != NULL) {
        free(drbgCtx->algName);
        drbgCtx->algName = NULL;
    }

    free(drbgCtx);
}
