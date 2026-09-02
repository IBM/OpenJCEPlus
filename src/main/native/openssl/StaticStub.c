/*
 * Copyright IBM Corp. 2023, 2026
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
#include <openssl/crypto.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"
#include <stdint.h>

// NOTE: These constants must match those defined in
//       com.ibm.crypto.plus.provider.openssl.NativeOpenSSLAdapter
//
#define VALUE_ID_FIPS_APPROVED_MODE 0
#define VALUE_ID_OSSL_INSTALL_PATH 1
#define VALUE_ID_OSSL_VERSION 2

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    initializeOCK
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_initializeOSSL(
    JNIEnv *env, jclass thisObj, jboolean isFIPS) {

    // Nothing to do. Method is a placeholder for future use.

    return 0;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    CTX_getValue
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_CTX_1getValue(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jint valueId) {
    static const char *functionName = "NativeInterface.CTX_getValue";
    char buffer[1024];  // Some values may be long
    const char *result = NULL;
    jstring retValue = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    switch (valueId) {
        case VALUE_ID_FIPS_APPROVED_MODE:
            // Nothing to do.
            return NULL;

        case VALUE_ID_OSSL_INSTALL_PATH:
            result = OpenSSL_version(OPENSSL_VERSION_STRING);
            break;

        case VALUE_ID_OSSL_VERSION:
            result = OPENSSL_info(OPENSSL_INFO_CONFIG_DIR);
            break;

        default:
            throwOSSLException(env, 0, "Invalid value id");
            return NULL;
    }

    if ((NULL == result) || (strcmp(result, "not available") != 0)) {
        throwOSSLException(env, 0, "OPENSSL_info or OpenSSL_version failed");
        return NULL;
    }

    buffer[sizeof(buffer) - 1] = 0;  // make sure null-terminated
    retValue = (*env)->NewStringUTF(env, buffer);

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retValue;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_getByteBufferPointer(
    JNIEnv *env, jclass unusedclass, jobject obj) {
    return (jlong)((intptr_t)(*env)->GetDirectBufferAddress(env, obj));
}
