/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLSymmetricCipher.h
 * @brief Symmetric cipher operations (AES, DES, ChaCha20, etc.) using OpenSSL.
 *
 * This header defines the interface for symmetric encryption and decryption
 * operations. It supports various cipher algorithms and modes including:
 * - AES (128, 192, 256-bit keys)
 * - DES and Triple DES
 * - ChaCha20
 * - Multiple modes: ECB, CBC, CTR, OFB, CFB
 *
 * The implementation uses OpenSSL's EVP interface for algorithm-independent
 * cipher operations with support for padding, streaming, and context reuse.
 */

#ifndef _OPENSSL_SYMMETRIC_CIPHER_H
#define _OPENSSL_SYMMETRIC_CIPHER_H

#include <jni.h>
#include <openssl/evp.h>

/**
 * @struct CipherContext
 * @brief Cipher context structure for symmetric operations.
 *
 * Maintains the state for symmetric cipher operations including
 * the OpenSSL context, cipher algorithm, and operation parameters.
 */
typedef struct CipherContext {
    EVP_CIPHER_CTX*   ctx;         /**< OpenSSL cipher context */
    const EVP_CIPHER* cipher;      /**< Cipher algorithm */
    int               padding;     /**< Padding mode (1=enabled, 0=disabled) */
    int               encrypt;     /**< Operation mode (1=encrypt, 0=decrypt) */
    int               blockSize;   /**< Cipher block size in bytes */
    unsigned char*    key;         /**< Encryption key (stored for reinit) */
    int               keyLen;      /**< Key length in bytes */
    unsigned char*    iv;          /**< Initialization vector (stored for reinit) */
    int               ivLen;       /**< IV length in bytes */
    int               tagLen;      /**< Authentication tag length (for AEAD modes) */
    int               updateCount; /**< Number of CCM_update calls since last CCM_init.
                                        OpenSSL CCM only supports a single EVP_CipherUpdate
                                        for data; a second call would corrupt the CBC-MAC. */
} CipherContext;

/**
 * Create a new cipher context for the specified algorithm.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherName Cipher algorithm name (e.g., "AES-256-CBC", "DES-EDE3-CBC")
 * @return Cipher context ID, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1create(
    JNIEnv* env, jclass cls, jlong osslContextId, jstring cipherName);

/**
 * Initialize cipher for encryption or decryption.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param encrypt Non-zero for encryption, zero for decryption
 * @param paddingId Padding mode (1=PKCS5/7, 0=no padding)
 * @param key Encryption/decryption key
 * @param iv Initialization vector (can be NULL for ECB mode)
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_init
 * Signature: (JJII[B[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1init(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jint paddingId, jbyteArray key, jbyteArray iv);

/**
 * Get the block size of the cipher in bytes.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @return Block size in bytes, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_getBlockSize
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getBlockSize(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId);

/**
 * Get the key length of the cipher in bytes.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @return Key length in bytes, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_getKeyLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getKeyLength(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId);

/**
 * Get the IV length of the cipher in bytes.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @return IV length in bytes, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_getIVLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1getIVLength(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId);

/**
 * Encrypt data (streaming operation).
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Input plaintext
 * @param inputOffset Offset in input array
 * @param inputLen Length of input data
 * @param output Output buffer for ciphertext
 * @param outputOffset Offset in output array
 * @param needsReinit JNI_TRUE to reinitialize cipher after operation
 * @return Number of bytes written to output, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_encryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1encryptUpdate(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/**
 * Decrypt data (streaming operation).
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Input ciphertext
 * @param inputOffset Offset in input array
 * @param inputLen Length of input data
 * @param output Output buffer for plaintext
 * @param outputOffset Offset in output array
 * @param needsReinit JNI_TRUE to reinitialize cipher after operation
 * @return Number of bytes written to output, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_decryptUpdate
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1decryptUpdate(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/**
 * Finalize encryption and apply padding if enabled.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Final input plaintext (can be empty)
 * @param inputOffset Offset in input array
 * @param inputLen Length of input data
 * @param output Output buffer for final ciphertext
 * @param outputOffset Offset in output array
 * @param needsReinit JNI_TRUE to reinitialize cipher after operation
 * @return Number of bytes written to output, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_encryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1encryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/**
 * Finalize decryption and remove padding if enabled.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Final input ciphertext (can be empty)
 * @param inputOffset Offset in input array
 * @param inputLen Length of input data
 * @param output Output buffer for final plaintext
 * @param outputOffset Offset in output array
 * @param needsReinit JNI_TRUE to reinitialize cipher after operation
 * @return Number of bytes written to output, or -1 on error
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_decryptFinal
 * Signature: (JJ[BII[BIIZ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1decryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jboolean needsReinit);

/**
 * Delete cipher context and free resources.
 *
 * @param env JNI environment
 * @param cls Java class
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID to delete
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CIPHER_1delete(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId);

#endif
