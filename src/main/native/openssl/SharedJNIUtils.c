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
#include <stdint.h>
#include <openssl/evp.h>
#include "Utils.h"

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EVP_PKEY_CTX_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EVP_1PKEY_1CTX_1create(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jstring algoName) {

    const char   *algoChars = NULL;
    EVP_PKEY_CTX *ctx       = NULL;
    jlong         ctxId     = 0;

    if (algoName == NULL) {
        throwOSSLException(env, 0, "EVP_PKEY_CTX_create: algoName is null");
        return 0;
    }

    if (!(algoChars = (*env)->GetStringUTFChars(env, algoName, NULL))) {
        throwOSSLException(env, 0, "EVP_PKEY_CTX_create: GetStringUTFChars failed");
        return 0;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algoChars, NULL);
    (*env)->ReleaseStringUTFChars(env, algoName, algoChars);

    if (ctx == NULL) {
        throwOSSLException(env, 0, "EVP_PKEY_CTX_create: EVP_PKEY_CTX_new_from_name failed");
        return 0;
    }

    ctxId = (jlong)((intptr_t)ctx);
    return ctxId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    EVP_PKEY_CTX_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_EVP_1PKEY_1CTX_1delete(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong pkeyCtxId) {

    EVP_PKEY_CTX *ctx = (EVP_PKEY_CTX *)((intptr_t)pkeyCtxId);

    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
}
