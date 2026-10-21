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

/* Ordinals from CurveUtil.CURVE, not OpenSSL NIDs. */
static const char *curveName(jint option) {
    switch (option) {
        case 0: return "X25519";
        case 1: return "X448";
        default: return NULL;
    }
}

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
    JNIEnv *env, jclass clazz, jlong contextId, jint option, jlong bufferPtr) {
    const char *name = curveName(option);
    EVP_PKEY *key = NULL;

    /*
     * Like Digest.c, use the default OpenSSL libctx. contextId is currently
     * a placeholder, NOT an OSSL_LIB_CTX pointer.
     */
    if (name == NULL || bufferPtr == 0) {
        throwOSSLException(env, 0, "XDH: unsupported curve or null output buffer");
        return 0;
    }

    key = EVP_PKEY_Q_keygen(NULL, NULL, name);
    if (key == NULL) {
        throwOSSLException(env, 0, "XDH: key generation failed");
        return 0;
    }

    if (!writePublicKey(env, key, bufferPtr)) {
        EVP_PKEY_free(key);
        return 0;
    }

    return (jlong)(intptr_t)key;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPrivateKey(
        JNIEnv *env,
        jclass clazz,
        jlong osslContextId,
        jbyteArray privateKeyBytes,
        jlong bufferPtr) {

    if (privateKeyBytes == NULL || bufferPtr == 0) {
        throwOSSLException(env, 0, "XDH: invalid private key input");
        return 0;
    }

    jsize size = (*env)->GetArrayLength(env, privateKeyBytes);

    unsigned char *keyBytesNative =
            (*env)->GetPrimitiveArrayCritical(env, privateKeyBytes, NULL);

    if (keyBytesNative == NULL) {
        return 0;
    }

    const unsigned char *pBytes = keyBytesNative;
    EVP_PKEY *pkey = NULL;

    d2i_AutoPrivateKey(&pkey, &pBytes, (long)size);

    (*env)->ReleasePrimitiveArrayCritical(
            env, privateKeyBytes, keyBytesNative, JNI_ABORT);

    if (pkey == NULL) {
        throwOSSLException(env, 0, "XDH: failed to decode private key");
        return 0;
    }

    if (!writePublicKey(env, pkey, bufferPtr)) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    return (jlong)(intptr_t)pkey;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1createPublicKey(
        JNIEnv *env,
        jclass clazz,
        jlong osslContextId,
        jbyteArray publicKeyBytes) {

    if (publicKeyBytes == NULL) {
        throwOSSLException(env, 0, "XDH: public key bytes are null");
        return 0;
    }

    jsize size = (*env)->GetArrayLength(env, publicKeyBytes);

    if (size == 0) {
        throwOSSLException(env, 0, "XDH: public key bytes are empty");
        return 0;
    }

    unsigned char *keyBytesNative =
            (*env)->GetPrimitiveArrayCritical(env, publicKeyBytes, NULL);

    if (keyBytesNative == NULL) {
        return 0;
    }

    const unsigned char *ptr = keyBytesNative;
    EVP_PKEY *pkey = NULL;

    d2i_PUBKEY(&pkey, &ptr, size);

    (*env)->ReleasePrimitiveArrayCritical(
            env, publicKeyBytes, keyBytesNative, JNI_ABORT);

    if (pkey == NULL) {
        throwOSSLException(env, 0, "XDH: failed to decode public key");
        return 0;
    }

    return (jlong)(intptr_t)pkey;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPrivateKeyBytes(
        JNIEnv *env,
        jclass clazz,
        jlong osslContextId,
        jlong xecKeyId) {

    EVP_PKEY *pkey = (EVP_PKEY *)(intptr_t)xecKeyId;

    if (pkey == NULL) {
        throwOSSLException(env, 0, "XDH: private key is null");
        return NULL;
    }

    unsigned char *encoded = NULL;
    int encodedLength = i2d_PrivateKey(pkey, &encoded);

    if (encodedLength <= 0) {
        OPENSSL_free(encoded);
        throwOSSLException(env, 0, "XDH: failed to encode private key");
        return NULL;
    }

    jbyteArray privateKeyBytes = (*env)->NewByteArray(env, encodedLength);

    if (privateKeyBytes == NULL) {
        OPENSSL_clear_free(encoded, encodedLength);
        return NULL;
    }

    (*env)->SetByteArrayRegion(
            env, privateKeyBytes, 0, encodedLength, (const jbyte *)encoded);

    OPENSSL_clear_free(encoded, encodedLength);

    if ((*env)->ExceptionCheck(env)) {
        return NULL;
    }

    return privateKeyBytes;
}

JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_XECKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass clazz, jlong contextId, jlong keyId) {
    unsigned char bytes[56];
    EVP_PKEY *key = (EVP_PKEY *)(intptr_t)keyId;
    size_t size = keySize(key);
    jbyteArray result;

    if (!size || EVP_PKEY_get_raw_public_key(key, bytes, &size) != 1) {
        throwOSSLException(env, 0, "XDH: public key export failed");
        return NULL;
    }

    result = (*env)->NewByteArray(env, (jsize)size);
    if (result != NULL) {
        (*env)->SetByteArrayRegion(
            env, result, 0, (jsize)size, (jbyte *)bytes);
    }
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

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privateKey, NULL);

    if (ctx == NULL) {
        throwOSSLException(env, 0, "XDH: failed to create context");
        return NULL;
    }

    int rc = EVP_PKEY_derive_init(ctx);

    if (rc != 1) {
        EVP_PKEY_CTX_free(ctx);
        throwOSSLException(env, 0, "XDH: failed to initialize key agreement");
        return NULL;
    }

    rc = EVP_PKEY_derive_set_peer(ctx, publicKey);

    if (rc != 1) {
        EVP_PKEY_CTX_free(ctx);
        throwOSSLException(env, 0, "XDH: failed to set peer public key");
        return NULL;
    }

    int required_len = EVP_PKEY_size(publicKey);

    if (required_len <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throwOSSLException(env, 0, "Derived secret size is zero");
        return NULL;
    }

    size_t secret_key_len = (size_t)required_len;

    jbyteArray secretBytes =
            (*env)->NewByteArray(env, (jsize)secret_key_len);

    if (secretBytes == NULL) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    unsigned char *secretBytesNative =
            (unsigned char *)(*env)->GetPrimitiveArrayCritical(
                    env, secretBytes, NULL);

    if (secretBytesNative == NULL) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    rc = EVP_PKEY_derive(ctx, secretBytesNative, &secret_key_len);

    (*env)->ReleasePrimitiveArrayCritical(
            env, secretBytes, secretBytesNative, 0);

    EVP_PKEY_CTX_free(ctx);

    if (rc != 1) {
        throwOSSLException(env, 0, "Failed to derive shared secret");
        return NULL;
    }

    if (secret_key_len != (size_t)required_len) {
        throwOSSLException(env, 0, "Unexpected shared secret length");
        return NULL;
    }

    return secretBytes;
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
