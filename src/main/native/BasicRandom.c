/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <jni.h>
#include <stdio.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include "Context.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RAND_nextBytes
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RAND_1nextBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray bytes) {
    static const char *functionName = "NativeInterface.RAND_nextbytes";

    ICC_CTX       *ockCtx      = (ICC_CTX *)((intptr_t)ockContextId);
    unsigned char *bytesNative = NULL;
    jboolean       isCopy;
    jint           size;
    int            rc = ICC_OK;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    bytesNative = (*env)->GetPrimitiveArrayCritical(env, bytes, &isCopy);
    if (bytesNative == NULL) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        size = (*env)->GetArrayLength(env, bytes);
#ifdef DEBUG_RANDOM_DETAIL
        gslogMessage("DETAIL_RANDOM size=%d", (int)size);
#endif
        rc = ICC_RAND_bytes(ockCtx, bytesNative, size);
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_RAND_BYTES failed");
        }
    }

    if (bytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, bytes, bytesNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RAND_setSeed
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RAND_1setSeed(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray seed) {
    static const char *functionName = "NativeInterface.RAND_setSeed";

    ICC_CTX       *ockCtx     = (ICC_CTX *)((intptr_t)ockContextId);
    unsigned char *seedNative = NULL;
    jboolean       isCopy;
    jint           size;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    seedNative = (*env)->GetPrimitiveArrayCritical(env, seed, &isCopy);
    if (seedNative == NULL) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        size = (*env)->GetArrayLength(env, seed);
#ifdef DEBUG_RANDOM_DETAIL
        gslogMessage("DETAIL_RANDOM size=%d", (int)size);
#endif

        ICC_RAND_seed(ockCtx, seedNative, size);
    }

    if (seedNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, seed, seedNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RAND_generateSeed
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RAND_1generateSeed(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray seed) {
    static const char *functionName = "NativeInterface.RAND_generateSeed";

    ICC_CTX       *ockCtx     = (ICC_CTX *)((intptr_t)ockContextId);
    unsigned char *seedNative = NULL;
    jboolean       isCopy;
    jint           size;
    ICC_STATUS     status;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    seedNative = (*env)->GetPrimitiveArrayCritical(env, seed, &isCopy);
    if (seedNative == NULL) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        size = (*env)->GetArrayLength(env, seed);

        ICC_GenerateRandomSeed(ockCtx, &status, size, seedNative);
#ifdef DEBUG_RANDOM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RAND size=%d", (int)size);
            gslogMessagePrefix("DETAIL_RAND size =%d", (int)size);
            gslogMessageHex((char *)seedNative, 0, (int)size, 0, 0, NULL);
        }
#endif
    }

    if (seedNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, seed, seedNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
