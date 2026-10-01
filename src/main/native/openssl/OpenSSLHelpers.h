/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLHelpers.h
 * @brief Common helper functions for OpenSSL JNI operations.
 *
 * This header provides a comprehensive set of utility functions used across
 * all OpenSSL native implementations. It centralizes common patterns for:
 * - Context validation and management
 * - JNI array and string handling with proper cleanup
 * - Parameter validation with consistent error reporting
 * - OpenSSL object creation and fetching
 * - Memory allocation with error handling
 *
 * These helpers improve code maintainability, reduce duplication, and ensure
 * consistent error handling across all OpenSSL operations.
 */

#ifndef _OPENSSL_HELPERS_H
#define _OPENSSL_HELPERS_H

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"

// Forward declarations
extern int debug;
void       setPendingOpenSSLException(JNIEnv* env, int code, const char* msg);
void       logOpenSSLError(const char* prefix);

//============================================================================
// Logging Helpers
//============================================================================

/**
 * Log function entry if debug mode is enabled.
 * @param functionName Name of the function being entered
 */
void logFunctionEntry(const char* functionName);

/**
 * Log function exit if debug mode is enabled.
 * @param functionName Name of the function being exited
 */
void logFunctionExit(const char* functionName);

//============================================================================
// Context Validation
//============================================================================

/**
 * Validate the context flag and return the appropriate OpenSSL context.
 * @param env JNI environment
 * @param fipsFlag Context selector (pass 0)
 * @param functionName Calling function name for error reporting
 * @param outContext Output parameter for the context pointer
 * @return 1 on success, 0 on failure (exception thrown)
 */
int validateAndGetContext(JNIEnv* env, jint fipsFlag, const char* functionName,
                          OpenSSLContext** outContext);

/**
 * Wire pre-created contexts into the dispatch table.
 * Must be called once from JNI_OnLoad / initializeOpenSSL before any
 * cryptographic operations. Both pointers may be NULL to force on-demand init.
 */
void initializeOpenSSLContexts(OpenSSLContext* nonFips, OpenSSLContext* fips);

//============================================================================
// String Helpers
//============================================================================

/**
 * Safely get UTF-8 string from Java string with error handling.
 * @param env JNI environment
 * @param javaString Java string object
 * @param functionName Calling function name for error reporting
 * @param errorMsg Error message if string is NULL
 * @return UTF-8 C string, or NULL on error (exception thrown)
 */
const char* getStringUTFCharsSafe(JNIEnv* env, jstring javaString,
                                  const char* functionName,
                                  const char* errorMsg);

/**
 * Release UTF-8 string obtained from Java string.
 * @param env JNI environment
 * @param javaString Original Java string object
 * @param str UTF-8 C string to release
 */
void cleanupStringUTFChars(JNIEnv* env, jstring javaString, const char* str);

//============================================================================
// Byte Array Helpers
//============================================================================

/**
 * Safely get byte array elements with error handling.
 * @param env JNI environment
 * @param array Java byte array
 * @param functionName Calling function name for error reporting
 * @param errorMsg Error message if array is NULL or access fails
 * @return Pointer to array elements, or NULL on error (exception thrown)
 */
jbyte* getByteArrayElementsSafe(JNIEnv* env, jbyteArray array,
                                const char* functionName, const char* errorMsg);

/**
 * Release byte array elements.
 * @param env JNI environment
 * @param array Java byte array
 * @param bytes Pointer to array elements
 * @param mode Release mode (JNI_COMMIT, JNI_ABORT, or 0)
 */
void cleanupByteArray(JNIEnv* env, jbyteArray array, jbyte* bytes, jint mode);

/**
 * Release key and IV byte arrays (convenience function).
 * @param env JNI environment
 * @param keyArray Key byte array
 * @param keyBytes Key array elements
 * @param ivArray IV byte array
 * @param ivBytes IV array elements
 */
void cleanupByteArrays(JNIEnv* env, jbyteArray keyArray, jbyte* keyBytes,
                       jbyteArray ivArray, jbyte* ivBytes);

/**
 * Release input and output byte arrays with optional commit.
 * @param env JNI environment
 * @param inputArray Input byte array
 * @param inputBytes Input array elements
 * @param outputArray Output byte array
 * @param outputBytes Output array elements
 * @param commitOutput JNI_TRUE to commit output changes, JNI_FALSE to abort
 */
void cleanupIOArrays(JNIEnv* env, jbyteArray inputArray, jbyte* inputBytes,
                     jbyteArray outputArray, jbyte* outputBytes,
                     jboolean commitOutput);

//============================================================================
// Validation Helpers
//============================================================================

/**
 * Validate that an integer value is within a specified range.
 * @param env JNI environment
 * @param value Value to validate
 * @param min Minimum allowed value (inclusive)
 * @param max Maximum allowed value (inclusive)
 * @param functionName Calling function name for error reporting
 * @param errorMsg Error message if validation fails
 * @return 1 if valid, 0 if invalid (exception thrown)
 */
int validateIntRange(JNIEnv* env, jint value, jint min, jint max,
                     const char* functionName, const char* errorMsg);

/**
 * Validate that a byte array length is within a specified range.
 * @param env JNI environment
 * @param array Byte array to validate
 * @param min Minimum allowed length (inclusive)
 * @param max Maximum allowed length (inclusive)
 * @param functionName Calling function name for error reporting
 * @param errorMsg Error message if validation fails
 * @return 1 if valid, 0 if invalid (exception thrown)
 */
int validateArrayLength(JNIEnv* env, jbyteArray array, jint min, jint max,
                        const char* functionName, const char* errorMsg);

/**
 * Validate offset and length parameters for array access.
 * @param env JNI environment
 * @param arrayLength Total length of the array
 * @param offset Starting offset
 * @param length Number of elements to access
 * @param functionName Calling function name for error reporting
 * @param errorMsg Error message if validation fails
 * @return 1 if valid, 0 if invalid (exception thrown)
 */
int validateOffsetAndLength(JNIEnv* env, jint arrayLength, jint offset,
                            jint length, const char* functionName,
                            const char* errorMsg);

/**
 * Validate that an output buffer has sufficient capacity.
 * @param env JNI environment
 * @param output Output byte array
 * @param outputOffset Starting offset in output array
 * @param requiredSize Required capacity from offset
 * @param functionName Calling function name for error reporting
 * @param errorMsg Error message if validation fails
 * @return 1 if valid, 0 if invalid (exception thrown)
 */
int validateOutputBuffer(JNIEnv* env, jbyteArray output, jint outputOffset,
                         jint requiredSize, const char* functionName,
                         const char* errorMsg);

//============================================================================
// OpenSSL Object Fetch Helpers
//============================================================================

/**
 * Safely create a cipher context.
 * @param env JNI environment
 * @param functionName Calling function name for error reporting
 * @param errorCode Error code to use if creation fails
 * @param errorMsg Error message if creation fails
 * @return EVP_CIPHER_CTX pointer, or NULL on error (exception thrown)
 */
EVP_CIPHER_CTX* createCipherCtxSafe(JNIEnv* env, const char* functionName,
                                    int errorCode, const char* errorMsg);

//============================================================================
// Memory Helpers
//============================================================================

/**
 * Safely allocate memory with error handling.
 * @param env JNI environment
 * @param size Number of bytes to allocate
 * @param errorMsg Error message if allocation fails
 * @return Pointer to allocated memory, or NULL on error (exception thrown)
 */
void* mallocSafe(JNIEnv* env, size_t size, const char* errorMsg);

/**
 * Safely create a new Java byte array.
 * @param env JNI environment
 * @param length Length of the array
 * @param errorMsg Error message if creation fails
 * @return Java byte array, or NULL on error (exception thrown)
 */
jbyteArray newByteArraySafe(JNIEnv* env, jsize length, const char* errorMsg);

//============================================================================
// AAD Processing Helper (for GCM/CCM)
//============================================================================

/**
 * Process Additional Authenticated Data for GCM/CCM modes.
 * @param env JNI environment
 * @param ctx Cipher context
 * @param aad AAD bytes
 * @param aadLen Length of AAD
 * @param functionName Calling function name for error reporting
 * @return 1 on success, 0 on failure (exception thrown)
 */
int processAAD(JNIEnv* env, EVP_CIPHER_CTX* ctx, const unsigned char* aad,
               int aadLen, const char* functionName);

/**
 * Process AAD from Java byte array for GCM/CCM modes.
 * Handles array acquisition, processing, and cleanup.
 * @param env JNI environment
 * @param ctx Cipher context
 * @param aad Java byte array containing AAD (can be NULL)
 * @param aadLen Length of AAD
 * @param functionName Calling function name for error reporting
 * @return 1 on success, 0 on failure (exception thrown)
 */
int processAADFromArray(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyteArray aad,
                        jint aadLen, const char* functionName);

/**
 * Extract authentication tag from input and set for verification.
 * @param env JNI environment
 * @param ctx Cipher context
 * @param input Input byte array containing ciphertext + tag
 * @param inputOffset Offset in input array
 * @param inputLen Total length (ciphertext + tag)
 * @param tagLen Length of authentication tag
 * @param ctrlType Control type (EVP_CTRL_GCM_SET_TAG or EVP_CTRL_CCM_SET_TAG)
 * @param functionName Calling function name for error reporting
 * @return 1 on success, 0 on failure (exception thrown)
 */
int extractAndSetTag(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyteArray input,
                     jint inputOffset, jint inputLen, jint tagLen, int ctrlType,
                     const char* functionName);

/**
 * Get authentication tag and append to output buffer.
 * @param env JNI environment
 * @param ctx Cipher context
 * @param outputBytes Output buffer (already acquired from JNI)
 * @param outputOffset Offset in output buffer
 * @param currentLen Current length of output (before tag)
 * @param tagLen Length of authentication tag
 * @param ctrlType Control type (EVP_CTRL_GCM_GET_TAG or EVP_CTRL_CCM_GET_TAG)
 * @param functionName Calling function name for error reporting
 * @return New total length (currentLen + tagLen) on success, -1 on failure
 */
int getAndAppendTag(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyte* outputBytes,
                    jint outputOffset, jint currentLen, jint tagLen,
                    int ctrlType, const char* functionName);

/**
 * Process zero-length input for authenticated encryption modes.
 * Required by OpenSSL for proper tag verification even with no ciphertext.
 * @param env JNI environment
 * @param ctx Cipher context
 * @param outputBytes Output buffer
 * @param outputOffset Offset in output buffer
 * @param functionName Calling function name for error reporting
 * @return 1 on success, 0 on failure (exception thrown)
 */
int processZeroLengthInput(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyte* outputBytes,
                           jint outputOffset, const char* functionName);

#endif
