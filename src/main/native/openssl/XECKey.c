/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"

static size_t keySize(EVP_PKEY *key) {
    if (key != NULL && EVP_PKEY_is_a(key, "X25519")) return 32;
    if (key != NULL && EVP_PKEY_is_a(key, "X448")) return 56;
    return 0;
}

static int writePublicKey(JNIEnv *env, EVP_PKEY *key, jlong bufferPtr) {
    size_t expected = keySize(key);

    if (bufferPtr == 0) {
        throwOSSLException(env, 0, "XDH: public key buffer is null");
        return 0;
    }

    if (expected == 0) {
        throwOSSLException(env, 0, "XDH: unsupported key type");
        return 0;
    }

    size_t size = expected;

    unsigned char *buffer =
            (unsigned char *)(intptr_t)bufferPtr;

    int result = EVP_PKEY_get_raw_public_key(key, buffer, &size);

    if (result != 1) {
        throwOSSLException(env, 0, "XDH: failed to export raw public key");
        return 0;
    }

    if (size != expected) {
        throwOSSLException(env, 0, "XDH: unexpected public key length");
        return 0;
    }

    return 1;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1generate(
    JNIEnv *env, jclass clazz, jlong contextId, jlong pkeyCtxId, jlong bufferPtr) {
    EVP_PKEY_CTX *tmpl = (EVP_PKEY_CTX *)(intptr_t)pkeyCtxId;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    jlong keyId = 0;

    if (tmpl == NULL || bufferPtr == 0) {
        throwOSSLException(env, 0,
                          "XDH: null key context or null output buffer");
        goto cleanup;
    }

    /* Duplicate the cached X25519/X448 context instead of creating a new one. */
    ctx = EVP_PKEY_CTX_dup(tmpl);
    if (ctx == NULL) {
        throwOSSLException(env, 0, "XDH: EVP_PKEY_CTX_dup failed");
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        throwOSSLException(env, 0, "XDH: EVP_PKEY_keygen_init failed");
        goto cleanup;
    }

    if (EVP_PKEY_generate(ctx, &key) != 1) {
        throwOSSLException(env, 0, "XDH: key generation failed");
        goto cleanup;
    }

    if (!writePublicKey(env, key, bufferPtr)) {
        goto cleanup;
    }

    keyId = (jlong)(intptr_t)key;
    key = NULL; /* Ownership transferred to the caller. */

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return keyId;
}


JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPrivateKey(
        JNIEnv *env,
        jclass clazz,
        jlong osslContextId,
        jbyteArray privateKeyBytes,
        jlong bufferPtr) {

    jlong keyId = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *keyBytesNative = NULL;
    const unsigned char *pBytes = NULL;
    jsize size = 0;

    if (privateKeyBytes == NULL || bufferPtr == 0) {
        throwOSSLException(env, 0, "XDH: invalid private key input");
        goto cleanup;
    }

    size = (*env)->GetArrayLength(env, privateKeyBytes);

    keyBytesNative =
            (*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, NULL);
    if (keyBytesNative == NULL) {
        goto cleanup; /* Preserve the pending JVM exception. */
    }

    pBytes = keyBytesNative;
    d2i_AutoPrivateKey(&pkey, &pBytes, (long)size);

    (*env)->ReleasePrimitiveArrayCritical(
            env, privateKeyBytes, keyBytesNative, JNI_ABORT);
    keyBytesNative = NULL;

    if (pkey == NULL) {
        throwOSSLException(env, 0, "XDH: failed to decode private key");
        goto cleanup;
    }

    if (!writePublicKey(env, pkey, bufferPtr)) {
        goto cleanup;
    }

    keyId = (jlong)(intptr_t)pkey;
    pkey = NULL; /* Ownership transferred to the caller. */

cleanup:
    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(
                env, privateKeyBytes, keyBytesNative, JNI_ABORT);
    }
    EVP_PKEY_free(pkey);
    return keyId;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPublicKey(
        JNIEnv *env,
        jclass clazz,
        jlong osslContextId,
        jbyteArray publicKeyBytes) {

    jlong keyId = 0;
    EVP_PKEY *pkey = NULL;
    unsigned char *keyBytesNative = NULL;
    const unsigned char *ptr = NULL;
    jsize size = 0;

    if (publicKeyBytes == NULL) {
        throwOSSLException(env, 0, "XDH: public key bytes are null");
        goto cleanup;
    }

    size = (*env)->GetArrayLength(env, publicKeyBytes);
    if (size == 0) {
        throwOSSLException(env, 0, "XDH: public key bytes are empty");
        goto cleanup;
    }

    keyBytesNative =
            (*env)->GetPrimitiveArrayCritical(env, publicKeyBytes, NULL);
    if (keyBytesNative == NULL) {
        goto cleanup; /* Preserve the pending JVM exception. */
    }

    ptr = keyBytesNative;
    d2i_PUBKEY(&pkey, &ptr, size);

    (*env)->ReleasePrimitiveArrayCritical(
            env, publicKeyBytes, keyBytesNative, JNI_ABORT);
    keyBytesNative = NULL;

    if (pkey == NULL) {
        throwOSSLException(env, 0, "XDH: failed to decode public key");
        goto cleanup;
    }

    keyId = (jlong)(intptr_t)pkey;
    pkey = NULL; /* Ownership transferred to the caller. */

cleanup:
    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(
                env, publicKeyBytes, keyBytesNative, JNI_ABORT);
    }
    EVP_PKEY_free(pkey);
    return keyId;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPrivateKeyBytes(
        JNIEnv *env,
        jclass clazz,
        jlong osslContextId,
        jlong xecKeyId) {

    EVP_PKEY *pkey = (EVP_PKEY *)(intptr_t)xecKeyId;
    unsigned char *encoded = NULL;
    int encodedLength = 0;
    jbyteArray privateKeyBytes = NULL;
    jbyteArray result = NULL;

    if (pkey == NULL) {
        throwOSSLException(env, 0, "XDH: private key is null");
        goto cleanup;
    }

    encodedLength = i2d_PrivateKey(pkey, &encoded);
    if (encodedLength <= 0) {
        encodedLength = 0;
        throwOSSLException(env, 0, "XDH: failed to encode private key");
        goto cleanup;
    }

    privateKeyBytes = (*env)->NewByteArray(env, encodedLength);
    if (privateKeyBytes == NULL) {
        goto cleanup; /* Preserve the pending JVM exception. */
    }

    (*env)->SetByteArrayRegion(
            env, privateKeyBytes, 0, encodedLength, (const jbyte *)encoded);
    if ((*env)->ExceptionCheck(env)) {
        goto cleanup;
    }

    result = privateKeyBytes;

cleanup:
    OPENSSL_clear_free(encoded, (size_t)encodedLength);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass clazz, jlong contextId, jlong keyId) {
    unsigned char bytes[56];
    EVP_PKEY *key = (EVP_PKEY *)(intptr_t)keyId;
    size_t size = keySize(key);
    jbyteArray result = NULL;

    if (!size || EVP_PKEY_get_raw_public_key(key, bytes, &size) != 1) {
        throwOSSLException(env, 0, "XDH: public key export failed");
        goto cleanup;
    }

    result = (*env)->NewByteArray(env, (jsize)size);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(
            env, result, 0, (jsize)size, (jbyte *)bytes);
    }

cleanup:
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1computeECDHSecret(
        JNIEnv *env,
        jclass clazz,
        jlong osslContextId,
        jlong genCtx,
        jlong pubXecKeyId,
        jlong privXecKeyId) {

    EVP_PKEY *publicKey = (EVP_PKEY *)(intptr_t)pubXecKeyId;
    EVP_PKEY *privateKey = (EVP_PKEY *)(intptr_t)privXecKeyId;

    EVP_PKEY_CTX *ctx = NULL;
    jbyteArray secretBytes = NULL;
    jbyteArray result = NULL;
    unsigned char *secretBytesNative = NULL;

    const char *errorMessage = NULL;
    int requiredLength = 0;
    size_t secretLength = 0;

    if (publicKey == NULL || privateKey == NULL) {
        errorMessage = "XDH: public or private key is null";
        goto cleanup;
    }

    ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (ctx == NULL) {
        errorMessage = "XDH: failed to create context";
        goto cleanup;
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
        errorMessage = "XDH: failed to initialize key agreement";
        goto cleanup;
    }

    if (EVP_PKEY_derive_set_peer(ctx, publicKey) != 1) {
        errorMessage = "XDH: failed to set peer public key";
        goto cleanup;
    }

    requiredLength = EVP_PKEY_size(publicKey);
    if (requiredLength <= 0) {
        errorMessage = "Derived secret size is zero";
        goto cleanup;
    }

    secretLength = (size_t)requiredLength;

    secretBytes = (*env)->NewByteArray(env, (jsize)requiredLength);
    if (secretBytes == NULL) {
        goto cleanup; /* Preserve the pending JVM exception. */
    }

    secretBytesNative =
            (unsigned char *)(*env)->GetPrimitiveArrayCritical(
                    env, secretBytes, NULL);

    if (secretBytesNative == NULL) {
        goto cleanup; /* Preserve the pending JVM exception. */
    }

    if (EVP_PKEY_derive(ctx, secretBytesNative, &secretLength) != 1) {
        errorMessage = "Failed to derive shared secret";
        goto cleanup;
    }

    if (secretLength != (size_t)requiredLength) {
        errorMessage = "Unexpected shared secret length";
        goto cleanup;
    }

    result = secretBytes;

cleanup:
    if (secretBytesNative != NULL) {
        if (result == NULL) {
            OPENSSL_cleanse(secretBytesNative, (size_t)requiredLength);
        }

        (*env)->ReleasePrimitiveArrayCritical(
                env, secretBytes, secretBytesNative, 0);
    }

    /*
     * Report errors only after releasing the critical array,
     * and preserve any exception already raised by the JVM.
     */
    if (errorMessage != NULL && !(*env)->ExceptionCheck(env)) {
        throwOSSLException(env, 0, errorMessage);
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}

JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1delete(
        JNIEnv *env,
        jclass clazz,
        jlong contextId,
        jlong keyId) {

    EVP_PKEY *pkey = (EVP_PKEY *)(intptr_t)keyId;

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
}
