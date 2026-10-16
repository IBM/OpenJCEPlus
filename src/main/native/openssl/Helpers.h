/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file Helpers.h
 * @brief Common helper functions for OpenSSL JNI operations.
 *
 * Provides reusable utilities for JNI exception throwing, array/string
 * access, and memory allocation. These helpers reduce duplication and
 * ensure consistent error handling across all OpenSSL native files.
 */

#ifndef _OPENSSL_HELPERS_H
#define _OPENSSL_HELPERS_H

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "ExceptionCodes.h"
#include "Utils.h"

//============================================================================
// Exception helpers
//============================================================================

/**
 * Throw a NullPointerException with the given message.
 */
void throwNPE(JNIEnv *env, const char *msg);

/**
 * Throw an OutOfMemoryError with the given message.
 */
void throwOOM(JNIEnv *env, const char *msg);

/**
 * Throw an IllegalStateException with the given message.
 */
void throwISE(JNIEnv *env, const char *msg);

//============================================================================
// String helpers
//============================================================================

/**
 * Get UTF-8 chars from a Java string, throwing OOM on failure.
 * Returns NULL and sets a pending exception on error.
 */
const char *getStringUTFCharsSafe(JNIEnv *env, jstring javaString,
                                  const char *errorMsg);

/**
 * Release UTF-8 chars obtained via getStringUTFCharsSafe.
 * Safe to call with NULL str.
 */
void releaseStringUTFChars(JNIEnv *env, jstring javaString, const char *str);

//============================================================================
// Byte array helpers
//============================================================================

/**
 * Pin a Java byte array, throwing OOM on failure.
 * Returns NULL and sets a pending exception on error.
 */
jbyte *getByteArrayElementsSafe(JNIEnv *env, jbyteArray array,
                                const char *errorMsg);

/**
 * Unpin a byte array. mode: 0 = copy back, JNI_ABORT = discard.
 * Safe to call with NULL bytes.
 */
void releaseByteArrayElements(JNIEnv *env, jbyteArray array, jbyte *bytes,
                              jint mode);

//============================================================================
// Memory helpers
//============================================================================

/**
 * malloc + memset(0), throwing OpenSSLException(OPENSSL_ALLOCATION_FAILED)
 * on failure. Returns NULL and sets a pending exception on error.
 */
void *mallocSafe(JNIEnv *env, size_t size, const char *errorMsg);

#endif
