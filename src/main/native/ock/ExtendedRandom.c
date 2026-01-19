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

#include "com_ibm_crypto_plus_provider_base_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    EXTRAND_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_EXTRAND_1create(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring algName) {
    static const char *functionName = "NativeInterface.EXTRAND_create";

    ICC_CTX      *ockCtx       = (ICC_CTX *)((intptr_t)ockContextId);
    const char   *algNameChars = NULL;
    ICC_PRNG     *ockPRNG      = NULL;
    ICC_PRNG_CTX *ockPRNGCtx   = NULL;
    SP800_90STATE spState;
    jlong         ockPRNGContextId = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    algNameChars = (*env)->GetStringUTFChars(env, algName, NULL);
    if (algNameChars == NULL) {
        throwOCKException(env, 0, "GetStringUTFChars() failed");
    } else {
#ifdef DEBUG_EXTENDED_RANDOM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_EXT_RANDOM algName=%s", algNameChars);
        }
#endif

        ockPRNG = ICC_get_RNGbyname(ockCtx, algNameChars);
        if (ockPRNG == NULL) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_getRNGbyname() failed");
        } else {
            ockPRNGCtx = ICC_RNG_CTX_new(ockCtx);
            if (ockPRNGCtx == NULL) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_RNG_CTX_new() failed");
            } else {
                spState = ICC_RNG_CTX_Init(ockCtx, ockPRNGCtx, ockPRNG, NULL, 0,
                                           0, 0);
                if ((spState == (SP800_90STATE)ICC_FAILURE) ||
                    (spState == SP800_90ERROR) || (spState == SP800_90CRIT)) {
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_RNG_CTX_Init() failed");
                } else {
                    ockPRNGContextId = (jlong)((intptr_t)ockPRNGCtx);
#ifdef DEBUG_EXTENDED_RANDOM_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_EXT_RANDOM iccpRNGContext=%lx",
                                     (long)ockPRNGContextId);
                    }
#endif
                }
            }
        }
    }

    if (algNameChars != NULL) {
        (*env)->ReleaseStringUTFChars(env, algName, algNameChars);
    }

    if ((ockPRNGCtx != NULL) && (ockPRNGContextId == 0)) {
        ICC_RNG_CTX_free(ockCtx, ockPRNGCtx);
        ockPRNGCtx = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return ockPRNGContextId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    EXTRAND_nextBytes
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_EXTRAND_1nextBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPRNGContextId,
    jbyteArray bytes) {
    static const char *functionName = "NativeInterface.EXTRAND_nextBytes";

    ICC_CTX       *ockCtx      = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_PRNG_CTX  *ockPRNGCtx  = (ICC_PRNG_CTX *)((intptr_t)ockPRNGContextId);
    unsigned char *bytesNative = NULL;
    jboolean       isCopy;
    jint           size;
    SP800_90STATE  spState;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_EXTENDED_RANDOM_DETAIL
        gslogMessage("DETAIL_EXT_RANDOM iccpRNGContext=%lx",
                     (long)ockPRNGContextId);
#endif
    }

    bytesNative = (*env)->GetPrimitiveArrayCritical(env, bytes, &isCopy);
    if (bytesNative == NULL) {
        throwOCKException(env, 0, "GetPrimitiveArrayCritical() failed");
    } else {
        size = (*env)->GetArrayLength(env, bytes);
#ifdef DEBUG_EXTENDED_RANDOM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_EXT_RANDOM size=%d", (int)size);
        }
#endif

        spState =
            ICC_RNG_Generate(ockCtx, ockPRNGCtx, bytesNative, size, NULL, 0);
        if ((spState == (SP800_90STATE)ICC_FAILURE) ||
            (spState == SP800_90ERROR) || (spState == SP800_90CRIT)) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_RNG_CTX_Init() failed");
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
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    EXTRAND_setSeed
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_EXTRAND_1setSeed(
    JNIEnv *env, jclass thisObj, jlong contextId, jlong ockPRNGContextId,
    jbyteArray seed) {
    static const char *functionName = "NativeInterface.EXTRAND_setSeed";

    ICC_CTX       *ockCtx     = (ICC_CTX *)((intptr_t)contextId);
    ICC_PRNG_CTX  *ockPRNGCtx = (ICC_PRNG_CTX *)((intptr_t)ockPRNGContextId);
    unsigned char *seedNative = NULL;
    jboolean       isCopy;
    jint           size;
    SP800_90STATE  spState;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_EXTENDED_RANDOM_DETAIL
        gslogMessage("DETAIL_EXT_RANDOM iccpRNGContext=%lx",
                     (long)ockPRNGContextId);
#endif
    }

    seedNative = (*env)->GetPrimitiveArrayCritical(env, seed, &isCopy);
    if (seedNative == NULL) {
        throwOCKException(env, 0, "GetPrimitiveArrayCritical() failed");
    } else {
        size = (*env)->GetArrayLength(env, seed);
#ifdef DEBUG_EXTENDED_RANDOM_DETAIL
        if (debug) {
            gslogMessage("DETAIL_EXT_RANDOM size=%d", (int)size);
        }
#endif

        spState = ICC_RNG_ReSeed(ockCtx, ockPRNGCtx, seedNative, size);
        if ((spState == (SP800_90STATE)ICC_FAILURE) ||
            (spState == SP800_90ERROR) || (spState == SP800_90CRIT)) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_RNG_CTX_Init() failed");
        }
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
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    EXTRAND_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_EXTRAND_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPRNGContextId) {
    static const char *functionName = "NativeInterface.EXTRAND_delete";

    ICC_CTX      *ockCtx     = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_PRNG_CTX *ockPRNGCtx = (ICC_PRNG_CTX *)((intptr_t)ockPRNGContextId);

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_EXTENDED_RANDOM_DETAIL
        gslogMessage("DETAIL_EXT_RANDOM iccpRNGContext=%lx",
                     (long)ockPRNGContextId);
#endif
    }
    if (ockPRNGCtx != NULL) {
        ICC_RNG_CTX_free(ockCtx, ockPRNGCtx);
        ockPRNGCtx = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
