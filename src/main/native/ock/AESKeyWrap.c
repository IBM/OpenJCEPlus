/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_base_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>
#include <string.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    CIPHER_KeyWraporUnwrap
 * Signature: (J[B[B[BI)V
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_CIPHER_1KeyWraporUnwrap(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray input,
    jbyteArray KEK, jint type) {
    ICC_CTX       *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    int            outputlen = 0;
    int            rv        = 0;
    jboolean       isCopy;
    jbyteArray     outBytes       = NULL;
    jbyteArray     retOutBytes    = NULL;
    unsigned char *inputNative    = NULL;
    unsigned char *outputLocal    = NULL;
    unsigned char *outBytesNative = NULL;
    unsigned char *KEKNative      = NULL;
    unsigned int   opType         = (unsigned int)type;
    unsigned int   inputSize      = 0;

    inputNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, input, &isCopy));

    if (NULL == inputNative) {
        throwOCKException(env, 0,
                          "Input is NULL from GetPrimitiveArrayCritical!");
        return retOutBytes;
    }

    KEKNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, KEK, &isCopy));

    if (NULL == KEKNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative,
                                              JNI_ABORT);
        throwOCKException(env, 0,
                          "KEK is NULL from GetPrimitiveArrayCritical!");
        return retOutBytes;
    }

    inputSize = (*env)->GetArrayLength(env, input);

    outputLocal = (unsigned char *)malloc(inputSize + 16);
    if (outputLocal == NULL) {
        throwOCKException(env, 0, "malloc failed");
    } else {
        const unsigned int keybits = ((*env)->GetArrayLength(env, KEK)) * 8;

        rv = ICC_SP800_38F_KW(ockCtx, inputNative, inputSize, outputLocal,
                              &outputlen, KEKNative, keybits, opType);
        if (ICC_NOT_IMPLEMENTED == rv) {
            throwOCKException(env, rv, "ICC_SP800_38F_KW not_supported");
        } else if (1 != rv) {
            throwOCKException(env, rv, "ICC_SP800_38F_KW:ICC_KW_WRAP failed");
        } else {
            outBytes = (*env)->NewByteArray(env, outputlen);
            if (outBytes == NULL) {
                throwOCKException(env, 0, "NewByteArray failed");
            } else {
                outBytesNative =
                    (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                        env, outBytes, &isCopy));
                if (outBytesNative == NULL) {
                    throwOCKException(
                        env, 0,
                        "Output is NULL from GetPrimitiveArrayCritical");
                } else {
                    memcpy(outBytesNative, outputLocal, outputlen);
                    retOutBytes = outBytes;
                }
            }
        }
    }

    if (outputLocal != NULL) {
        free(outputLocal);
        outputLocal = NULL;
    }

    if (outBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, outBytes, outBytesNative, 0);
    }

    (*env)->ReleasePrimitiveArrayCritical(env, KEK, KEKNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, JNI_ABORT);

    return retOutBytes;
}
