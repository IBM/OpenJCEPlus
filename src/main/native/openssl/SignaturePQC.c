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
#include <openssl/params.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    PQC_SIGNATURE_sign
 * Signature: (JJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_PQC_1SIGNATURE_1sign(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong pKeyId,
    jbyteArray data) {

    EVP_PKEY          *pkey           = (EVP_PKEY *)((intptr_t)pKeyId);
    EVP_PKEY_CTX      *sctx           = NULL;
    EVP_SIGNATURE     *sig_alg        = NULL;
    unsigned char     *dataNative     = NULL;
    unsigned char     *sigBuf         = NULL;
    unsigned char     *sigBytesNative = NULL;
    jbyteArray        sigBytes        = NULL;
    jboolean          isCopy          = 0;
    size_t            dataLen         = 0;
    size_t            sigLen          = 0;
    jbyteArray        retSigBytes     = NULL;
    const char        *algName        = NULL;

    if (pkey == NULL || data == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: pkey or data is null");
        return NULL;
    }

    /* Derive the algorithm name from the key (e.g. "ML-DSA-44") */
    algName = EVP_PKEY_get0_type_name(pkey);
    if (algName == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_get0_type_name failed");
        return NULL;
    }

    sig_alg = EVP_SIGNATURE_fetch(NULL, algName, NULL);
    if (sig_alg == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_SIGNATURE_fetch failed");
        return NULL;
    }

    sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (sctx == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_CTX_new_from_pkey failed");
        goto cleanup;
    }

    /* No context string params needed for standard signing */
    if (1 != EVP_PKEY_sign_message_init(sctx, sig_alg, NULL)) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_sign_message_init failed");
        goto cleanup;
    }

    dataLen    = (size_t)((*env)->GetArrayLength(env, data));
    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data, &isCopy));
    if (dataNative == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    /* Determine signature length */
    if (1 != EVP_PKEY_sign(sctx, NULL, &sigLen, dataNative, dataLen)) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_sign (size query) failed");
        goto cleanup;
    }

    sigBuf = (unsigned char *)malloc(sigLen);
    if (sigBuf == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: malloc failed");
        goto cleanup;
    }

    if (1 != EVP_PKEY_sign(sctx, sigBuf, &sigLen, dataNative, dataLen)) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_sign failed");
        goto cleanup;
    }

    (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
    dataNative = NULL;

    sigBytes = (*env)->NewByteArray(env, (jsize)sigLen);
    if (sigBytes == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: NewByteArray failed");
        goto cleanup;
    }

    sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, sigBytes, &isCopy));
    if (sigBytesNative == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: GetPrimitiveArrayCritical (sig) failed");
        goto cleanup;
    }

    memcpy(sigBytesNative, sigBuf, sigLen);
    (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    retSigBytes = sigBytes;

cleanup:
    if (dataNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
        dataNative = NULL;
    }
    if ((sigBytes != NULL) && (retSigBytes == NULL)) {
        (*env)->DeleteLocalRef(env, sigBytes);
    }
    if (sigBuf != NULL) {
        free(sigBuf);
    }
    if (sctx != NULL) {
        EVP_PKEY_CTX_free(sctx);
    }
    if (sig_alg != NULL) {
        EVP_SIGNATURE_free(sig_alg);
    }
    
    return retSigBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    PQC_SIGNATURE_verify
 * Signature: (JJ[B[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_PQC_1SIGNATURE_1verify(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong pKeyId,
    jbyteArray sigBytes, jbyteArray data) {

    EVP_PKEY          *pkey           = (EVP_PKEY *)((intptr_t)pKeyId);
    EVP_PKEY_CTX      *sctx           = NULL;
    EVP_SIGNATURE     *sig_alg        = NULL;
    unsigned char     *sigBytesNative = NULL;
    unsigned char     *dataNative     = NULL;
    jboolean          isCopy          = 0;
    size_t            sigLen          = 0;
    size_t            dataLen         = 0;
    jboolean          verified        = JNI_FALSE;
    const char        *algName        = NULL;

    if (pkey == NULL || sigBytes == NULL || data == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: pkey, sigBytes, or data is null");
        return JNI_FALSE;
    }

    algName = EVP_PKEY_get0_type_name(pkey);
    if (algName == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_PKEY_get0_type_name failed");
        return JNI_FALSE;
    }

    sig_alg = EVP_SIGNATURE_fetch(NULL, algName, NULL);
    if (sig_alg == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_SIGNATURE_fetch failed");
        return JNI_FALSE;
    }

    sctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (sctx == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_PKEY_CTX_new_from_pkey failed");
        goto cleanup;
    }

    if (1 != EVP_PKEY_verify_message_init(sctx, sig_alg, NULL)) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_PKEY_verify_message_init failed");
        goto cleanup;
    }

    sigLen         = (size_t)((*env)->GetArrayLength(env, sigBytes));
    sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, sigBytes, &isCopy));
    if (sigBytesNative == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: GetPrimitiveArrayCritical (sig) failed");
        goto cleanup;
    }

    dataLen    = (size_t)((*env)->GetArrayLength(env, data));
    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data, &isCopy));
    if (dataNative == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: GetPrimitiveArrayCritical (data) failed");
        goto cleanup;
    }

    if (1 != EVP_PKEY_verify(sctx, sigBytesNative, sigLen, dataNative, dataLen)) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_PKEY_verify failed");
        goto cleanup;
    }

    verified = JNI_TRUE;

cleanup:
    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, JNI_ABORT);
        sigBytesNative = NULL;
    }
    if (dataNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
        dataNative = NULL;
    }
    if (sctx != NULL) {
        EVP_PKEY_CTX_free(sctx);
    }
    if (sig_alg != NULL) {
        EVP_SIGNATURE_free(sig_alg);
    }

    return verified;
}
