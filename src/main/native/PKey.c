/*
 * Copyright IBM Corp. 2023
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

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    PKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_PKEY_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong pkeyId) {
    static const char *functionName = "NativeInterface.PKEY_delete";

    ICC_CTX      *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY *ockPKey = (ICC_EVP_PKEY *)((intptr_t)pkeyId);

    if (debug) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_PKEY_DETAIL
    if (debug) {
        gslogMessage("DETAIL_PKEY pkeyId=%lx", (long)pkeyId);
    }
#endif
    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }
}
