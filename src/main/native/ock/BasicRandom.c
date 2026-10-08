/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeOCKImplementation.h"
#include "Utils.h"
#include "Context.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeOCKImplementation
 * Method:    RAND_generateSeed
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeOCKImplementation_RAND_1generateSeed(
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
