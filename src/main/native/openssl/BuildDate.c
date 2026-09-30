/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file BuildDate.c
 * @brief Provides build date information for the OpenSSL native library.
 *
 * This file implements functionality to retrieve the build date and time
 * of the native library, which can be useful for version tracking and
 * debugging purposes.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "OpenSSLLogging.h"
#include <stdint.h>

/**
 * Retrieves the build date and time of the native library.
 *
 * This function returns a string containing the build date and time of the
 * native library. The date is determined at compile time using preprocessor
 * macros in the following priority:
 * 1. BUILD_DATE macro if defined
 * 2. __DATE__ and __TIME__ macros if available
 * 3. __DATE__ macro only if __TIME__ is not available
 * 4. "<UNKNOWN>" if no date information is available
 *
 * On z/OS (MVS), the string is converted to ISO8859-1 encoding.
 *
 * @param env The JNI environment pointer
 * @param thisObj The class object (unused)
 * @return A Java String containing the build date, or NULL if allocation fails
 */
//============================================================================
// getLibraryBuildDate - Get the build date and time of the native library
//============================================================================
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_getLibraryBuildDate(
    JNIEnv* env, jclass thisObj) {
    static const char* functionName =
        "NativeOpenSSLImplementation.getLibraryBuildDate";
    const char* buildDateString = NULL;
    jstring     retValue        = NULL;

    logFunctionEntry(functionName);

#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif

#if defined(BUILD_DATE)
    buildDateString = BUILD_DATE;
#elif defined(__DATE__) && defined(__TIME__)
    buildDateString = __DATE__ " " __TIME__;
#elif defined(__DATE__)
    buildDateString = __DATE__;
#else
    buildDateString = "<UNKNOWN>";
#endif

#ifdef __MVS__
#pragma convert(pop)
#endif

    if (buildDateString != NULL) {
        retValue = (*env)->NewStringUTF(env, buildDateString);
    }

    logFunctionExit(functionName);

    return retValue;
}
