/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLGCM.h
 * @brief GCM (Galois/Counter Mode) authenticated encryption using OpenSSL.
 *
 * This header defines the interface for AES-GCM authenticated encryption
 * operations. GCM mode provides both confidentiality and authenticity,
 * combining counter mode encryption with Galois field multiplication for
 * authentication.
 *
 * GCM is widely used in modern cryptographic protocols including TLS 1.2/1.3,
 * IPsec, and SSH. It is specified in NIST SP 800-38D.
 *
 * Key advantages of GCM:
 * - Parallel processing capability
 * - High performance on modern hardware
 * - Flexible IV lengths (recommended: 12 bytes for optimal performance)
 * - Strong authentication guarantees
 */

#ifndef _OPENSSL_GCM_H
#define _OPENSSL_GCM_H

#include <jni.h>

/**
 * @defgroup GCM_Constants GCM Mode Constants
 * @{
 */

/** Maximum authentication tag size in bytes (128 bits) */
#define MAX_GCM_TAG_SIZE 16

/** Minimum authentication tag size in bytes (32 bits) */
#define MIN_GCM_TAG_SIZE 4

/** Maximum initialization vector size in bytes (implementation limit) */
#define MAX_GCM_IV_SIZE 1024

/** Minimum initialization vector size in bytes */
#define MIN_GCM_IV_SIZE 1

/** Error code returned when GCM tag verification fails during decryption */
#define OPENSSL_TAG_MISMATCH_ERROR -6

/** @} */  // end of GCM_Constants

/**
 * Initialize a GCM cipher context for encryption or decryption.
 *
 * Sets up the GCM cipher with the specified key, IV (nonce), and tag length.
 * The tag length must be between 4-16 bytes. While GCM supports IV lengths
 * from 1-1024 bytes, 12 bytes is strongly recommended for optimal performance.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID from previous cipher creation
 * @param encrypt Non-zero for encryption, zero for decryption
 * @param key Byte array containing the encryption key
 * @param iv Byte array containing the initialization vector (nonce)
 * @param tagLen Length of the authentication tag (4-16 bytes)
 *
 * @throws OpenSSLException if initialization fails or parameters are invalid
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_init
 * Signature: (JJII[B[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1init(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray key, jbyteArray iv, jint tagLen);

/**
 * Update GCM cipher with input data and optional AAD.
 *
 * Processes input data through the GCM cipher. Additional Authenticated Data
 * (AAD) can be provided for authentication without encryption. This function
 * can be called multiple times for streaming operations.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param encrypt Non-zero for encryption, zero for decryption
 * @param input Input data byte array
 * @param inputOffset Offset in input array
 * @param inputLen Length of input data to process
 * @param output Output buffer for processed data
 * @param outputOffset Offset in output array
 * @param aad Additional Authenticated Data (can be NULL)
 * @param aadLen Length of AAD
 * @return Number of bytes written to output, or -1 on error
 *
 * @throws OpenSSLException if update operation fails
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_update
 * Signature: (JJII[BII[BI[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1update(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jint encrypt,
    jbyteArray input, jint inputOffset, jint inputLen, jbyteArray output,
    jint outputOffset, jbyteArray aad, jint aadLen);

/**
 * Finalize GCM encryption and generate authentication tag.
 *
 * Completes the GCM encryption operation, processes any remaining input data,
 * and generates the authentication tag. The tag is appended to the ciphertext
 * in the output buffer.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Final input data (can be NULL)
 * @param inputOffset Offset in input array
 * @param inputLen Length of final input data
 * @param output Output buffer (must be large enough for ciphertext + tag)
 * @param outputOffset Offset in output array
 * @param aad Additional Authenticated Data (can be NULL)
 * @param aadLen Length of AAD
 * @param tagLen Length of authentication tag to generate
 * @return Total bytes written (ciphertext + tag), or -1 on error
 *
 * @throws OpenSSLException if finalization fails
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_encryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1encryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen);

/**
 * Finalize GCM decryption and verify authentication tag.
 *
 * Completes the GCM decryption operation, processes the ciphertext, and
 * verifies the authentication tag. The input must include both the ciphertext
 * and the appended authentication tag.
 *
 * Tag verification is performed automatically. If verification fails,
 * OPENSSL_TAG_MISMATCH_ERROR is returned and an exception is thrown.
 *
 * @param env JNI environment pointer
 * @param cls Java class reference
 * @param contextId Pointer to OpenSSLContext structure (cast from jlong)
 * @param cipherId Cipher context ID
 * @param input Input data containing ciphertext + tag
 * @param inputOffset Offset in input array
 * @param inputLen Total length of input (ciphertext + tag)
 * @param output Output buffer for decrypted plaintext
 * @param outputOffset Offset in output array
 * @param aad Additional Authenticated Data (must match encryption AAD)
 * @param aadLen Length of AAD
 * @param tagLen Length of authentication tag
 * @return Number of plaintext bytes written, or OPENSSL_TAG_MISMATCH_ERROR
 *         if tag verification fails, or -1 on other errors
 *
 * @throws OpenSSLException if decryption or tag verification fails
 *
 * Class:     com_ibm_crypto_plus_provider_openssl_OpenSSLNativeInterface
 * Method:    GCM_decryptFinal
 * Signature: (JJ[BII[BI[BII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_GCM_1decryptFinal(
    JNIEnv* env, jclass cls, jlong osslContextId, jlong cipherId, jbyteArray input,
    jint inputOffset, jint inputLen, jbyteArray output, jint outputOffset,
    jbyteArray aad, jint aadLen, jint tagLen);

#endif
