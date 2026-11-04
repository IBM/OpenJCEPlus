/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "Utils.h"

/* Security strength (bits) requested from the DRBG. */
#define DRBG_STRENGTH 256

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
    int           success     = 0;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (bytes == NULL) {
        throwOSSLException(env, 0, "bytes array is null");
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
        snprintf(fullMsg, sizeof(fullMsg),
                 "RAND_generateSeed failed: %s (error code: %lu)", errMsg, err);
        throwOSSLException(env, 0, fullMsg);
        goto cleanup;
    }

    success = 1;

cleanup:
    if (bytesNative != NULL) {
        releaseByteArrayElements(env, bytes, bytesNative, success ? 0 : JNI_ABORT);
    }
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
    OSSL_PARAM    params[2];
    unsigned long err = 0;
    char          errMsg[512];
    char          fullMsg[768];
    jlong         retVal        = 0;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (algName == NULL) {
        throwOSSLException(env, 0, "algName is null");
        return 0;
    }

    algNameChars = getStringUTFCharsSafe(env, algName,
                                         "Failed to get algorithm name");
    if (algNameChars == NULL) {
        return 0;
    }

    /* Map Java algorithm names to OpenSSL EVP digest names.
     * OpenSSL's HASH-DRBG "digest" parameter must be an EVP_MD name;
     * "SHA-256"/"SHA-512" are the canonical aliases recognised by OpenSSL 3.x.
     * Any other name is rejected so a weak digest can never be selected. */
    if (strcmp(algNameChars, "SHA256") == 0) {
        digestName = "SHA-256";
    } else if (strcmp(algNameChars, "SHA512") == 0) {
        digestName = "SHA-512";
    } else {
        snprintf(errMsg, sizeof(errMsg), "Unsupported DRBG algorithm: %s",
                 algNameChars);
        throwOSSLException(env, 0, errMsg);
        goto cleanup;
    }

    rand = EVP_RAND_fetch(NULL, opensslAlg, NULL);
    if (rand == NULL) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        snprintf(fullMsg, sizeof(fullMsg),
                 "Failed to fetch DRBG algorithm %s: %s", opensslAlg, errMsg);
        throwOSSLException(env, 0, fullMsg);
        goto cleanup;
    }

    ctx = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    rand = NULL;

    if (ctx == NULL) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        snprintf(fullMsg, sizeof(fullMsg),
                 "Failed to create DRBG context: %s", errMsg);
        throwOSSLException(env, 0, fullMsg);
        goto cleanup;
    }

    /* Instantiate the DRBG with the digest algorithm passed as params.
     * Per OpenSSL 3 EVP_RAND design, instantiation params (including the
     * digest selection) must be passed to EVP_RAND_instantiate, not set
     * via a separate EVP_RAND_CTX_set_params call on an uninstantiated ctx. */
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)digestName, 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_RAND_instantiate(ctx, DRBG_STRENGTH, 0, NULL, 0, params)) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        snprintf(fullMsg, sizeof(fullMsg), "Failed to instantiate DRBG: %s",
                 errMsg);
        throwOSSLException(env, 0, fullMsg);
        goto cleanup;
    }

    retVal = (jlong)(intptr_t)ctx;
    ctx = NULL; /* ownership transferred to caller */

cleanup:
    releaseStringUTFChars(env, algName, algNameChars);
    if (ctx != NULL) {
        EVP_RAND_CTX_free(ctx);
    }
    return retVal;
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
    EVP_RAND_CTX  *ctx         = (EVP_RAND_CTX *)(intptr_t)drbgContextId;
    jbyte         *bytesNative = NULL;
    jsize          bytesLen    = 0;
    unsigned long  err         = 0;
    char           errMsg[256];
    char           fullMsg[512];
    int            success     = 0;

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (ctx == NULL) {
        throwOSSLException(env, 0, "DRBG context is null or invalid");
        return;
    }

    if (bytes == NULL) {
        throwOSSLException(env, 0, "bytes array is null");
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

    if (!EVP_RAND_generate(ctx, (unsigned char *)bytesNative,
                           (size_t)bytesLen, DRBG_STRENGTH, 0, NULL, 0)) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        snprintf(fullMsg, sizeof(fullMsg), "EVP_RAND_generate failed: %s",
                 errMsg);
        throwOSSLException(env, 0, fullMsg);
        goto cleanup;
    }

    success = 1;

cleanup:
    if (bytesNative != NULL) {
        releaseByteArrayElements(env, bytes, bytesNative, success ? 0 : JNI_ABORT);
    }
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
    EVP_RAND_CTX  *ctx        = (EVP_RAND_CTX *)(intptr_t)drbgContextId;
    unsigned char *seedCopy   = NULL;
    jsize          seedLen    = 0;
    unsigned long  err        = 0;
    char           errMsg[256];
    char           fullMsg[512];

    (void)cls;
    (void)osslContextId;

    ERR_clear_error();

    if (ctx == NULL) {
        throwOSSLException(env, 0, "DRBG context is null or invalid");
        return;
    }

    if (seed == NULL) {
        return; /* Silently ignore null seed */
    }

    seedLen = (*env)->GetArrayLength(env, seed);
    if (seedLen <= 0) {
        return;
    }

    /* Copy the seed into a private buffer so it can be wiped after use
     * without touching the caller's Java array. */
    seedCopy = (unsigned char *)mallocSafe(env, (size_t)seedLen,
                                           "Failed to allocate seed buffer");
    if (seedCopy == NULL) {
        goto cleanup;
    }

    (*env)->GetByteArrayRegion(env, seed, 0, seedLen, (jbyte *)seedCopy);
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    if (!EVP_RAND_reseed(ctx, 0, NULL, 0, seedCopy, (size_t)seedLen)) {
        err = ERR_get_error();
        ERR_error_string_n(err, errMsg, sizeof(errMsg));
        snprintf(fullMsg, sizeof(fullMsg), "EVP_RAND_reseed failed: %s", errMsg);
        throwOSSLException(env, 0, fullMsg);
        goto cleanup;
    }

cleanup:
    if (seedCopy != NULL) {
        OPENSSL_cleanse(seedCopy, (size_t)seedLen);
        free(seedCopy);
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EXTRAND_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EXTRAND_1delete
  (JNIEnv *env, jclass cls, jlong osslContextId, jlong drbgContextId)
{
    EVP_RAND_CTX *ctx = (EVP_RAND_CTX *)(intptr_t)drbgContextId;

    (void)env;
    (void)cls;
    (void)osslContextId;

    if (ctx != NULL) {
        EVP_RAND_CTX_free(ctx);
    }
}
