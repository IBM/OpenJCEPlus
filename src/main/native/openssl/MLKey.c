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
 * Method:    MLKEY_generate
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_MLKEY_1generate(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jstring cipherName) {

    EVP_PKEY_CTX  *ctx       = NULL;
    EVP_PKEY      *pkey      = NULL;
    const char    *algoChars = NULL;
    jlong         mlkeyId    = 0;

    if (cipherName == NULL) {
        throwOSSLException(env, 0, "MLKEY_generate: cipherName is null");
        return 0;
    }

    if (!(algoChars = (*env)->GetStringUTFChars(env, cipherName, NULL))) {
        throwOSSLException(env, 0, "MLKEY_generate: GetStringUTFChars failed");
        return 0;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, algoChars, NULL);
    if (ctx == NULL) {
        throwOSSLException(env, 0, "MLKEY_generate: EVP_PKEY_CTX_new_from_name failed");
        goto cleanup;
    }

    if (1 != EVP_PKEY_keygen_init(ctx)) {
        throwOSSLException(env, 0, "MLKEY_generate: EVP_PKEY_keygen_init failed");
        goto cleanup;
    }

    if (1 != EVP_PKEY_generate(ctx, &pkey)) {
        throwOSSLException(env, 0, "MLKEY_generate: EVP_PKEY_generate failed");
        goto cleanup;
    }

    mlkeyId = (jlong)((intptr_t)pkey);
    pkey = NULL; /* ownership transferred to caller via mlkeyId */

cleanup:
    (*env)->ReleaseStringUTFChars(env, cipherName, algoChars);
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    MLKEY_createPrivateKey
 * Signature: (JLjava/lang/String;[B)J
 *
 * privateKeyBytes is an OctetString-encoded raw private key (0x04 0x82 HH LL <raw>).
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_MLKEY_1createPrivateKey(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jstring cipherName,
    jbyteArray privateKeyBytes) {

    EVP_PKEY           *pkey      = NULL;
    unsigned char      *encNative = NULL;
    unsigned char      *rawKey    = NULL;
    const char         *algoChars = NULL;
    jboolean           isCopy     = 0;
    jlong              mlkeyId    = 0;
    size_t             encLen     = 0;
    size_t             rawLen     = 0;

    if (privateKeyBytes == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPrivateKey: privateKeyBytes is null");
        return 0;
    }

    encLen    = (size_t)((*env)->GetArrayLength(env, privateKeyBytes));
    encNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, &isCopy));
    if (encNative == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPrivateKey: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    /* Strip the OctetString wrapper to get the raw private key */
    rawKey = decode_octet_string(encNative, encLen, &rawLen);
    (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes, encNative, JNI_ABORT);
    encNative = NULL;

    if (rawKey == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPrivateKey: failed to decode OctetString");
        goto cleanup;
    }

    if (!(algoChars = (*env)->GetStringUTFChars(env, cipherName, NULL))) {
        throwOSSLException(env, 0, "MLKEY_createPrivateKey: GetStringUTFChars failed");
        goto cleanup;
    }

    pkey = EVP_PKEY_new_raw_private_key_ex(NULL, algoChars, NULL, rawKey, rawLen);
    if (pkey == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPrivateKey: EVP_PKEY_new_raw_private_key_ex failed");
        goto cleanup;
    }

    mlkeyId = (jlong)((intptr_t)pkey);
    pkey = NULL;

cleanup:
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (algoChars != NULL) {
        (*env)->ReleaseStringUTFChars(env, cipherName, algoChars);
    }
    if (rawKey != NULL) {
        memset(rawKey, 0, rawLen);
        free(rawKey);
    }

    return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    MLKEY_createPublicKey
 * Signature: (JLjava/lang/String;[B)J
 *
 * publicKeyBytes is a BitString-encoded raw public key (0x03 0x82 HH LL 0x00 <raw>).
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_MLKEY_1createPublicKey(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jstring cipherName,
    jbyteArray publicKeyBytes) {

    EVP_PKEY      *pkey        = NULL;
    unsigned char *encNative   = NULL;
    unsigned char *rawKey      = NULL;
    const char    *algoChars   = NULL;
    jboolean       isCopy      = 0;
    jlong          mlkeyId     = 0;
    size_t         encLen      = 0;
    size_t         rawLen      = 0;

    if (publicKeyBytes == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPublicKey: publicKeyBytes is null");
        return 0;
    }

    encLen    = (size_t)((*env)->GetArrayLength(env, publicKeyBytes));
    encNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, publicKeyBytes, &isCopy));
    if (encNative == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPublicKey: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    /* Strip the BitString wrapper to get the raw public key */
    rawKey = decode_bit_string(encNative, encLen, &rawLen);
    (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes, encNative, JNI_ABORT);
    encNative = NULL;

    if (rawKey == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPublicKey: failed to decode BitString");
        goto cleanup;
    }

    if (!(algoChars = (*env)->GetStringUTFChars(env, cipherName, NULL))) {
        throwOSSLException(env, 0, "MLKEY_createPublicKey: GetStringUTFChars failed");
        goto cleanup;
    }

    pkey = EVP_PKEY_new_raw_public_key_ex(NULL, algoChars, NULL, rawKey, rawLen);
    if (pkey == NULL) {
        throwOSSLException(env, 0, "MLKEY_createPublicKey: EVP_PKEY_new_raw_public_key_ex failed");
        goto cleanup;
    }

    mlkeyId = (jlong)((intptr_t)pkey);
    pkey = NULL;

cleanup:
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (algoChars != NULL) {
        (*env)->ReleaseStringUTFChars(env, cipherName, algoChars);
    }
    if (rawKey != NULL) {
        free(rawKey);
    }

    return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    MLKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 *
 * Returns an OctetString-encoded raw private key (0x04 0x82 HH LL <raw>).
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_MLKEY_1getPrivateKeyBytes(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong mlkeyId) {

    EVP_PKEY      *pkey           = (EVP_PKEY *)((intptr_t)mlkeyId);
    unsigned char *rawKey         = NULL;
    unsigned char *encoded        = NULL;
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    size_t         rawLen         = 0;
    size_t         encLen         = 0;
    jbyteArray     retKeyBytes    = NULL;

    if (pkey == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPrivateKeyBytes: pkey is null");
        return NULL;
    }

    /* First call to get the size */
    if ((1 != EVP_PKEY_get_raw_private_key(pkey, NULL, &rawLen)) || (rawLen == 0)) {
        throwOSSLException(env, 0, "MLKEY_getPrivateKeyBytes: EVP_PKEY_get_raw_private_key (size) failed");
        return NULL;
    }

    rawKey = (unsigned char *)malloc(rawLen);
    if (rawKey == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPrivateKeyBytes: malloc failed");
        return NULL;
    }

    if (1 != EVP_PKEY_get_raw_private_key(pkey, rawKey, &rawLen)) {
        throwOSSLException(env, 0, "MLKEY_getPrivateKeyBytes: EVP_PKEY_get_raw_private_key failed");
        goto cleanup;
    }

    /* Wrap in OctetString encoding */
    encoded = encode_octet_string(rawKey, rawLen, &encLen);
    if (encoded == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPrivateKeyBytes: encode_octet_string failed");
        goto cleanup;
    }

    keyBytes = (*env)->NewByteArray(env, (jsize)encLen);
    if (keyBytes == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPrivateKeyBytes: NewByteArray failed");
        goto cleanup;
    }

    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
    if (keyBytesNative == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPrivateKeyBytes: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    memcpy(keyBytesNative, encoded, encLen);
    (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
    retKeyBytes = keyBytes;

cleanup:
    if ((keyBytes != NULL) && (retKeyBytes == NULL)) {
        (*env)->DeleteLocalRef(env, keyBytes);
    }
    if (encoded != NULL) {
        memset(encoded, 0, encLen);
        free(encoded);
    }
    if (rawKey != NULL) {
        memset(rawKey, 0, rawLen);
        free(rawKey);
    }

    return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    MLKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 *
 * Returns a BitString-encoded raw public key (0x03 0x82 HH LL 0x00 <raw>).
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_MLKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong mlkeyId) {

    EVP_PKEY      *pkey           = (EVP_PKEY *)((intptr_t)mlkeyId);
    unsigned char *rawKey         = NULL;
    unsigned char *encoded        = NULL;
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    size_t         rawLen         = 0;
    size_t         encLen         = 0;
    jbyteArray     retKeyBytes    = NULL;

    if (pkey == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPublicKeyBytes: pkey is null");
        return NULL;
    }

    /* First call to get the size */
    if ((1 != EVP_PKEY_get_raw_public_key(pkey, NULL, &rawLen)) || (rawLen == 0)) {
        throwOSSLException(env, 0, "MLKEY_getPublicKeyBytes: EVP_PKEY_get_raw_public_key (size) failed");
        return NULL;
    }

    rawKey = (unsigned char *)malloc(rawLen);
    if (rawKey == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPublicKeyBytes: malloc failed");
        return NULL;
    }

    if (1 != EVP_PKEY_get_raw_public_key(pkey, rawKey, &rawLen)) {
        throwOSSLException(env, 0, "MLKEY_getPublicKeyBytes: EVP_PKEY_get_raw_public_key failed");
        goto cleanup;
    }

    /* Wrap in BitString encoding */
    encoded = encode_bit_string(rawKey, rawLen, &encLen);
    if (encoded == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPublicKeyBytes: encode_bit_string failed");
        goto cleanup;
    }

    keyBytes = (*env)->NewByteArray(env, (jsize)encLen);
    if (keyBytes == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPublicKeyBytes: NewByteArray failed");
        goto cleanup;
    }

    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, keyBytes, &isCopy));
    if (keyBytesNative == NULL) {
        throwOSSLException(env, 0, "MLKEY_getPublicKeyBytes: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    memcpy(keyBytesNative, encoded, encLen);
    (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
    retKeyBytes = keyBytes;

cleanup:
    if ((keyBytes != NULL) && (retKeyBytes == NULL)) {
        (*env)->DeleteLocalRef(env, keyBytes);
    }
    if (encoded != NULL) {
        free(encoded);
    }
    if (rawKey != NULL) {
        free(rawKey);
    }

    return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    MLKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_MLKEY_1delete(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong mlkeyId) {

    EVP_PKEY *pkey = (EVP_PKEY *)((intptr_t)mlkeyId);

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
}
