/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLUtils.h
 * @brief Core utility functions for OpenSSL JNI integration.
 *
 * This header provides fundamental utilities for OpenSSL operations including:
 * - Context management
 * - Exception handling and error reporting
 * - Debug logging infrastructure
 * - OpenSSL error string extraction
 *
 * These utilities form the foundation for all OpenSSL native operations
 * and ensure consistent error handling and logging across the codebase.
 */

#ifndef _OPENSSL_UTILS_H
#define _OPENSSL_UTILS_H

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"

/** Return code for successful operations */
#define OPENSSL_SUCCESS 0

/** Return code for failed operations */
#define OPENSSL_FAILURE -1

/**
 * Macro to safely free memory and set pointer to NULL.
 * Prevents double-free errors and use-after-free bugs.
 */
#define FREE_AND_NULL(ptr) \
    if ((ptr) != NULL) {   \
        free((ptr));       \
        (ptr) = NULL;      \
    }

/** Global debug flag - set to non-zero to enable debug logging */
extern int debug;

//============================================================================
// Logging Functions
//============================================================================

/** Log function entry (if debug enabled) */
int gslogFunctionEntry(const char* functionName);

/** Log error message */
int gslogError(const char* formatString, ...);

/** Log informational message */
int gslogMessage(const char* formatString, ...);

/** Log message with prefix */
int gslogMessagePrefix(const char* formatString, ...);

/** Log binary data as hexadecimal */
int gslogMessageHex(char byte[], int offset, int length, int spaceAfter,
                    int newlineAfter, char* newlinePrefix);

/** Log function exit (if debug enabled) */
int gslogFunctionExit(const char* functionName);

//============================================================================
// Exception and Error Handling
//============================================================================

/**
 * Set a pending OpenSSLException in the JVM with specified error code and message.
 *
 * IMPORTANT: Unlike Java's 'throw' keyword, this function does NOT immediately stop
 * execution. It sets a pending exception that will be thrown when the native code
 * returns to Java. Callers MUST check for errors and return early after calling
 * this function to ensure proper exception handling.
 *
 * @param env JNI environment
 * @param code Error code from OpenSSLExceptionCodes.h
 * @param msg Error message describing the error condition
 */
void setPendingOpenSSLException(JNIEnv* env, int code, const char* msg);

/**
 * Eagerly initialise the cached GlobalRef for OpenSSLException and its
 * constructors. Must be called from JNI_OnLoad before any cryptographic
 * operations to eliminate the lazy-init data race.
 * @param env JNI environment (must be valid at load time)
 */
void initOpenSSLExceptionClass(JNIEnv* env);

/**
 * Delete the cached GlobalRef for OpenSSLException.
 * Must be called from JNI_OnUnload to prevent a dangling reference if the
 * library is ever unloaded and reloaded.
 * @param env JNI environment (must be valid at unload time)
 */
void cleanupOpenSSLExceptionClass(JNIEnv* env);

/**
 * Get the current OpenSSL error as a string.
 * @return Dynamically allocated error string (caller must free)
 */
char* getOpenSSLErrorString(void);

/**
 * Log the current OpenSSL error with a prefix.
 * @param prefix Prefix string for the log message
 */
void logOpenSSLError(const char* prefix);

/**
 * Log binary data as hexadecimal with a prefix.
 * @param data Binary data to log
 * @param length Length of data
 * @param prefix Prefix string for the log message
 */
void logHexData(const unsigned char* data, int length, const char* prefix);

/**
 * Get the OpenSSLException class reference.
 * @param env JNI environment
 * @return Java class reference for OpenSSLException
 */
jclass getOpenSSLExceptionClass(JNIEnv* env);

//============================================================================
// Context Management
//============================================================================

/**
 * Create a properly configured OpenSSL context.
 * Used internally; exposed for OpenSSLJNI.c to create and register contexts.
 * @param env JNI environment
 * @param isFIPS Reserved; pass 0
 * @return Heap-allocated context, or NULL on error (exception thrown)
 */
OpenSSLContext* createContext(JNIEnv* env, int isFIPS);

/**
 * Free an OpenSSL context and all its associated providers.
 * Safe to call with NULL.
 * @param context Context to free
 */
void freeInternalContext(OpenSSLContext* context);

/**
 * Validate a cipher handle against the adapter-selected OpenSSL mode marker.
 *
 * @param env JNI environment
 * @param fipsFlag Non-zero for FIPS mode, zero for non-FIPS mode
 * @param cipherId Native cipher handle
 * @param functionName Calling function name for error reporting
 * @param outCipherCtx Output parameter for the cipher context
 * @return 1 on success, 0 on failure (exception thrown)
 */
struct CipherContext;

int validateCipherContext(JNIEnv* env, jint fipsFlag, jlong cipherId,
                          const char* functionName,
                          struct CipherContext** outCipherCtx);

#endif
