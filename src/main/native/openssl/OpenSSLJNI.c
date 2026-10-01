/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLJNI.c
 * @brief JNI entry point and context lifecycle management for OpenSSL
 * integration.
 *
 * This file implements the JNI boundary layer for the OpenSSL native bridge,
 * providing the interface between Java (NativeOpenSSLImplementation) and the
 * native OpenSSL C code. Key responsibilities include:
 * - JNI_OnLoad for library initialization
 * - Context creation and destruction (initializeOpenSSL/cleanupOpenSSL)
 * - Context map management for tracking active contexts
 * - Context value queries (CTX_getValue)
 * - ByteBuffer pointer access for direct memory operations
 *
 * The implementation maintains a context map to track active OpenSSL
 * contexts and ensures proper resource cleanup on library unload.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLHelpers.h"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    /* Declare all locals at top of block for C89 compatibility (MSVC) */
    unsigned long opensslVersion;
    JNIEnv*       env      = NULL;
    char*         debugEnv = NULL;
    jclass        sysCls   = NULL;
    jmethodID     getProp  = NULL;
    jstring       propName = NULL;
    jstring       propVal  = NULL;
    const char*   val      = NULL;

    /* Require OpenSSL 3.5.0+ (matches minOpenSSLVersion in NativeOpenSSLAdapter.java) */
    opensslVersion = OpenSSL_version_num();
    if (opensslVersion < 0x30500000L) {
        fprintf(stderr,
                "[OpenSSL JNI] ERROR: OpenSSL 3.5.0 or later is required.\n");
        fprintf(stderr,
                "[OpenSSL JNI] Current version: %s (0x%08lx)\n",
                OpenSSL_version(OPENSSL_VERSION), opensslVersion);
        fprintf(stderr,
                "[OpenSSL JNI] This library uses OpenSSL 3.5+ APIs "
                "(EVP_MD_fetch, OSSL_LIB_CTX, etc.) which are not available "
                "in older versions.\n");
        fflush(stderr);
        return JNI_ERR;
    }

    /* Obtain JNIEnv for system property lookup */
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK) {
        env = NULL;
    }

    /* 1. Check environment variable: OPENSSL_DEBUG=1|true */
    debugEnv = getenv("OPENSSL_DEBUG");
    if (debugEnv != NULL &&
        (strcmp(debugEnv, "1") == 0 || strcmp(debugEnv, "true") == 0)) {
        debug = 1;
    }

    /* 2. Check JVM system property: -Djceplus.openssl.debug=true|1 */
    if (!debug && env != NULL) {
        sysCls  = (*env)->FindClass(env, "java/lang/System");
        getProp = sysCls ? (*env)->GetStaticMethodID(env, sysCls,
                      "getProperty",
                      "(Ljava/lang/String;)Ljava/lang/String;") : NULL;
        if (getProp) {
            propName = (*env)->NewStringUTF(env, "jceplus.openssl.debug");
            propVal  = propName ? (jstring)(*env)->CallStaticObjectMethod(
                           env, sysCls, getProp, propName) : NULL;
            if (propVal) {
                val = (*env)->GetStringUTFChars(env, propVal, NULL);
                if (val &&
                    (strcmp(val, "1") == 0 || strcmp(val, "true") == 0)) {
                    debug = 1;
                }
                if (val) (*env)->ReleaseStringUTFChars(env, propVal, val);
            }
            if (propName) (*env)->DeleteLocalRef(env, propName);
        }
    }

    if (debug) {
        fprintf(stderr,
                "[OpenSSL JNI] Debug logging ENABLED\n");
        fprintf(stderr, "[OpenSSL JNI] Loaded with OpenSSL version: %s\n",
                OpenSSL_version(OPENSSL_VERSION));
        fflush(stderr);
    }

    /* R-2: Eagerly cache OpenSSLException GlobalRef and constructors. */
    if (env != NULL) {
        initOpenSSLExceptionClass(env);
    }

    return JNI_VERSION_1_8;
}

//============================================================================
// JNI Method Implementations
//============================================================================

/**
 * Initialize OpenSSL - Returns a context ID for compatibility with Java layer.
 *
 * NOTE: This function exists for API compatibility. It creates a context only
 * to validate that initialization succeeds for the requested mode.
 *
 * The returned ID is a marker (1 for non-FIPS, 2 for FIPS) selected by the
 * Java adapter layer.
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_initializeOSSL(
    JNIEnv* env, jclass cls, jboolean isFIPS) {
    static const char* functionName =
        "NativeOpenSSLImplementation.initializeOSSL";

    logFunctionEntry(functionName);

    /* Create a real OpenSSL context with proper provider isolation and
     * register it so validateAndGetContext() uses the correct OSSL_LIB_CTX
     * for all subsequent EVP_CIPHER_fetch / EVP_MD_fetch calls.
     *
     * validateAndGetContext() will create a context on demand if one is not
     * yet registered.  We call it here to eagerly initialise so that any
     * provider load failure is surfaced immediately rather than on first use.
     * If a context for this mode is already registered the existing one is
     * reused and no new allocation is performed, preventing a leak. */
    OpenSSLContext* ctx = NULL;
    if (!validateAndGetContext(env, isFIPS ? 1 : 0, functionName, &ctx)) {
        /* validateAndGetContext already set the exception */
        logFunctionExit(functionName);
        return -1;
    }

    jlong contextId = isFIPS ? 2 : 1;

#ifdef DEBUG_OPENSSL_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_OPENSSL OpenSSL initialized with context ID %ld, FIPS "
            "mode: %d",
            (long)contextId, isFIPS);
    }
#endif

    logFunctionExit(functionName);
    return contextId;
}

/**
 * Cleanup OpenSSL - No-op for compatibility.
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_cleanupOpenSSL(
    JNIEnv* env, jclass cls, jlong contextId) {
    static const char* functionName =
        "NativeOpenSSLImplementation.cleanupOpenSSL";

    logFunctionEntry(functionName);
    if (debug) {
        gslogMessage(
            "DETAIL_OPENSSL cleanupOpenSSL called for context %ld (no-op)",
            contextId);
    }
    logFunctionExit(functionName);

    // No-op: cleanup is handled by the caller/language side lifecycle.
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) == JNI_OK && env != NULL) {
        cleanupOpenSSLExceptionClass(env);
    }
}

/**
 * Get context value - Returns OpenSSL version or install path.
 *
 * NOTE: contextId is only used as a mode marker from the Java layer.
 * The information returned is global to the OpenSSL installation.
 */
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CTX_1getValue(
    JNIEnv* env, jclass cls, jlong contextId, jint valueId) {
    static const char* functionName =
        "NativeOpenSSLImplementation.CTX_getValue";

    logFunctionEntry(functionName);

    jstring result = NULL;

    switch (valueId) {
        case VALUE_FIPS_APPROVED_MODE:
            // FIPS mode is determined by the fipsFlag parameter passed to each
            // operation Context ID 2 indicates FIPS mode was requested during
            // initialization
            result =
                (*env)->NewStringUTF(env, (contextId == 2) ? "true" : "false");
            break;

        case VALUE_OPENSSL_VERSION:
            result =
                (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_VERSION));
            break;

        case VALUE_OPENSSL_INSTALL_PATH:
            result = (*env)->NewStringUTF(env, OpenSSL_version(OPENSSL_DIR));
            break;

        default:
            setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED, "Invalid value ID");
            break;
    }

    logFunctionExit(functionName);
    return result;
}

//============================================================================
// getByteBufferPointer - Get native pointer from direct ByteBuffer
//============================================================================
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_getByteBufferPointer(
    JNIEnv* env, jclass cls, jobject buffer) {
    static const char* functionName =
        "NativeOpenSSLImplementation.getByteBufferPointer";

    logFunctionEntry(functionName);

    void* ptr = (*env)->GetDirectBufferAddress(env, buffer);

    logFunctionExit(functionName);
    return (jlong)ptr;
}
