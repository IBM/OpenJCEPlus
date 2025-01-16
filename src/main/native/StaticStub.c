/*
 * Copyright IBM Corp. 2023, 2024
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
#include "ExceptionCodes.h"
#include "Context.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    initializeOCK
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_initializeOCK(
    JNIEnv *env, jclass thisObj, jboolean isFIPS) {
    static const char *functionName = "NativeInterface.initializeOCK";

    ICC_CTX   *ockCtx  = NULL;
    int        retcode = ICC_OK;
    ICC_STATUS status;

    com_ibm_crypto_plus_provider_initialize();

    if (debug) {
        gslogFunctionEntry(functionName);
        gslogMessage("isFIPS=%s", isFIPS ? "true" : "false");
    }

    ockCtx = ICC_Init(&status, NULL);
    if (ockCtx == NULL) {
        throwOCKException(env, 0, "ICC_Init failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    if (debug) {
        gslogMessage("ICC_Status mode: %d", status.mode);
    }
#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
    retcode = ICC_SetValue(ockCtx, &status, ICC_FIPS_APPROVED_MODE,
                           isFIPS ? "on" : "off");
#ifdef __MVS__
#pragma convert(pop)
#endif
    if ((retcode == ICC_FAILURE) || (ICC_OK != status.majRC)) {
        throwOCKException(env, 0, "Could not set ICC_FIPS_APPROVED_MODE");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    retcode = ICC_Attach(ockCtx, &status);
    if (retcode != ICC_OSSL_SUCCESS) {
        throwOCKException(env, GKR_OCK_ATTACH_FAILED, NULL);
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    retcode = ICC_GetStatus(ockCtx, &status);
    if (retcode != ICC_OSSL_SUCCESS) {
        throwOCKException(env, 0, "ICC_GetStatus failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    if (isFIPS) {
        if (!(status.mode & ICC_FIPS_FLAG)) {
            throwOCKException(env, 0, "Context is not in FIPS mode");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return 0;
        }
    } else {
        if (status.mode & ICC_FIPS_FLAG) {
            throwOCKException(env, 0, "Context is in FIPS mode");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return 0;
        }
    }

    if (debug) {
        if (status.mode & ICC_FIPS_FLAG) {
            gslogMessage("Context is in FIPS mode");
        } else {
            gslogMessage("Context is in non-FIPS mode");
        }
    }

    if (status.mode & ICC_ERROR_FLAG) {
        throwOCKException(env, GKR_FIPS_MODE_INVALID, NULL);
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    if (debug) {
        gslogMessage("ICC_Status mode: %d", status.mode);
        gslogMessage("ICC ockCtx : %d", (long)ockCtx);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jlong)((intptr_t)ockCtx);
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    CTX_getValue
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_CTX_1getValue(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jint valueId) {
    static const char *functionName = "NativeInterface.CTX_getValue";

    ICC_CTX           *ockCtx     = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_VALUE_IDS_ENUM iccValueId = 0;
    int                rc         = ICC_OSSL_SUCCESS;
    ICC_STATUS         status;
    char buffer[1024];  // Some values such as the ICC_INSTALL_PATH may be long
    jstring retValue = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    switch (valueId) {
        case VALUE_ID_FIPS_APPROVED_MODE:
            iccValueId = ICC_FIPS_APPROVED_MODE;
            break;

        case VALUE_ID_OCK_INSTALL_PATH:
            iccValueId = ICC_INSTALL_PATH;
            break;

        case VALUE_ID_OCK_VERSION:
            iccValueId = ICC_VERSION;
            break;

        default:
            throwOCKException(env, 0, "Invalid value id");
            rc = ICC_OSSL_FAILURE;
    }

    if (rc == ICC_OSSL_SUCCESS) {
        rc = ICC_GetValue(ockCtx, &status, iccValueId, buffer, sizeof(buffer));
        if ((rc == ICC_FAILURE) || (ICC_OK != status.majRC)) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_GetValue failed");
        } else {
            buffer[sizeof(buffer) - 1] = 0;  // make sure null-terminated

            retValue = (*env)->NewStringUTF(env, buffer);
        }
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retValue;
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_getByteBufferPointer(
    JNIEnv *env, jclass unusedclass, jobject obj) {
    return (jlong)((intptr_t)(*env)->GetDirectBufferAddress(env, obj));
}
