/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    KEM_encapsulate
 * Signature: (JJ[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEM_1encapsulate(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong pKeyId,
    jbyteArray wrappedKey, jbyteArray randomKey) {

    EVP_PKEY       *pkey             = (EVP_PKEY *)((intptr_t)pKeyId);
    EVP_PKEY_CTX   *ctx              = NULL;
    jboolean       isCopy            = 0;
    unsigned char  *wrappedKeyNative = NULL;
    unsigned char  *genKeyNative     = NULL;
    size_t         wrappedkeylen     = 0;
    size_t         genkeylen         = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) {
        throwOSSLException(env, 0, "KEM_encapsulate: EVP_PKEY_CTX_new_from_pkey failed");
        return;
    }

    if (1 != EVP_PKEY_encapsulate_init(ctx, NULL)) {
        throwOSSLException(env, 0, "KEM_encapsulate: EVP_PKEY_encapsulate_init failed");
        goto cleanup;
    }

    wrappedkeylen    = (size_t)((*env)->GetArrayLength(env, wrappedKey));
    genkeylen        = (size_t)((*env)->GetArrayLength(env, randomKey));

    wrappedKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, wrappedKey, &isCopy));
    if (wrappedKeyNative == NULL) {
        throwOSSLException(env, 0, "KEM_encapsulate: GetPrimitiveArrayCritical (wrapped key) failed");
        goto cleanup;
    }
    genKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, randomKey, &isCopy));
    if (genKeyNative == NULL) {
        throwOSSLException(env, 0, "KEM_encapsulate: GetPrimitiveArrayCritical (random key) failed");
        goto cleanup;
    }

    if (1 != EVP_PKEY_encapsulate(ctx, wrappedKeyNative, &wrappedkeylen, genKeyNative, &genkeylen)) {
        throwOSSLException(env, 0, "KEM_encapsulate: EVP_PKEY_encapsulate failed");
    }

cleanup:
    if (genKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative, 0);
        genKeyNative = NULL;
    }
    if (wrappedKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative, 0);
        wrappedKeyNative = NULL;
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    KEM_decapsulate
 * Signature: (JJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_KEM_1decapsulate(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong pKeyId,
    jbyteArray wrappedKey) {

    EVP_PKEY       *pkey             = (EVP_PKEY *)((intptr_t)pKeyId);
    EVP_PKEY_CTX   *ctx              = NULL;
    jboolean       isCopy            = 0;
    unsigned char  *wrappedKeyNative = NULL;
    unsigned char  *genkeylocal      = NULL;
    unsigned char  *genKeyNative     = NULL;
    size_t         wrappedkeylen     = 0;
    size_t         genkeylen         = 0;
    jbyteArray     randomKey         = NULL;
    jbyteArray     retRndKeyBytes    = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) {
        throwOSSLException(env, 0, "KEM_decapsulate: EVP_PKEY_CTX_new_from_pkey failed");
        return NULL;
    }

    if (1 != EVP_PKEY_decapsulate_init(ctx, NULL)) {
        throwOSSLException(env, 0, "KEM_decapsulate: EVP_PKEY_decapsulate_init failed");
        goto cleanup;
    }

    wrappedKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, wrappedKey, &isCopy));
    if (wrappedKeyNative == NULL) {
        throwOSSLException(env, 0, "KEM_decapsulate: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    wrappedkeylen = (size_t)((*env)->GetArrayLength(env, wrappedKey));

    if (1 != EVP_PKEY_decapsulate(ctx, NULL, &genkeylen, wrappedKeyNative, wrappedkeylen)) {
        throwOSSLException(env, 0, "KEM_decapsulate: EVP_PKEY_decapsulate (size query) failed");
        goto cleanup;
    }

    genkeylocal = (unsigned char *)malloc(genkeylen);
    if (genkeylocal == NULL) {
        throwOSSLException(env, 0, "KEM_decapsulate: malloc failed");
        goto cleanup;
    }

    if (1 != EVP_PKEY_decapsulate(ctx, genkeylocal, &genkeylen, wrappedKeyNative, wrappedkeylen)) {
        throwOSSLException(env, 0, "KEM_decapsulate: EVP_PKEY_decapsulate failed");
        goto cleanup;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative, JNI_ABORT);
    wrappedKeyNative = NULL;

    randomKey = (*env)->NewByteArray(env, (jsize)genkeylen);
    if (randomKey == NULL) {
        throwOSSLException(env, 0, "KEM_decapsulate: NewByteArray failed");
        goto cleanup;
    }

    genKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, randomKey, &isCopy));
    if (genKeyNative == NULL) {
        throwOSSLException(env, 0, "KEM_decapsulate: GetPrimitiveArrayCritical (out) failed");
        goto cleanup;
    }

    memcpy(genKeyNative, genkeylocal, genkeylen);
    (*env)->ReleasePrimitiveArrayCritical(env, randomKey, genKeyNative, 0);
    retRndKeyBytes = randomKey;

cleanup:
    if (wrappedKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, wrappedKey, wrappedKeyNative, JNI_ABORT);
        wrappedKeyNative = NULL;
    }
    if (genkeylocal != NULL) {
        free(genkeylocal);
    }
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (randomKey != NULL && retRndKeyBytes == NULL) {
        (*env)->DeleteLocalRef(env, randomKey);
    }

    return retRndKeyBytes;
}
