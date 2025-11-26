/*
 * Copyright IBM Corp. 2025
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
#include <string.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    PBE_doFinal
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_PBE_1doFinal(
    JNIEnv* env, jclass thisObj, jlong contextId, jstring algorithm,
    jbyteArray password, jbyteArray salt, jbyteArray input, jint iterations,
    jint is_en) {
    static const char* functionName   = "NativeInterface.PBE_doFinal";
    ICC_CTX*           ockCtx         = (ICC_CTX*)((intptr_t)contextId);
    ICC_X509_ALGOR*    algor          = NULL;
    const char*        text           = NULL;
    const char*        passwordNative = NULL;
    unsigned char*     saltNative     = NULL;
    unsigned char*     inputNative    = NULL;
    unsigned char*     resultNative   = NULL;
    jbyteArray         resultText     = NULL;
    jboolean           isCopy         = 0;
    int                id             = 0;
    int                passwordLength = 0;
    int                saltLength     = 0;
    int                inputLength    = 0;
    int                dataLength     = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    // Validation is assumed by the caller for the context, algorithm,
    // password, salt, input.

    // Get the OID.
    text = (*env)->GetStringUTFChars(env, algorithm, NULL);
    if (NULL == text) {
#ifdef DEBUG_PBE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBE FAILURE: Failed to get algorithm(OID)");
        }
#endif
        throwOCKException(env, 0, "Failed to get algorithm(OID)");
        goto cleanup;
    }

    // Get the NID.
    id = ICC_OBJ_txt2nid(ockCtx, text);
    if (0 == id) {
#ifdef DEBUG_PBE_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_PBE FAILURE: Failed to get the NID of PBE algorithm");
        }
#endif
        throwOCKException(env, 0, "Failed to get the NID of PBE algorithm");
        goto cleanup;
    }

    // Get the salt.
    saltNative = (*env)->GetPrimitiveArrayCritical(env, salt, &isCopy);
    if (NULL == saltNative) {
#ifdef DEBUG_PBE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBE FAILURE: Failed to get salt");
        }
#endif
        throwOCKException(env, 0, "Failed to get salt");
        goto cleanup;
    }
    saltLength = (*env)->GetArrayLength(env, salt);

    // Get the algorithm configuration.
    algor = ICC_PKCS5_pbe_set(ockCtx, id, iterations, saltNative, saltLength);
    if (NULL == algor) {
#ifdef DEBUG_PBE_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_PBE FAILURE: Failed to get the blob containing PBE "
                "algorithm configuration");
        }
#endif
        throwOCKException(
            env, 0,
            "Failed to get the blob containing PBE algorithm configuration");
        goto cleanup;
    }

    // Get the password.
    passwordNative = (*env)->GetPrimitiveArrayCritical(env, password, &isCopy);
    if (NULL == passwordNative) {
#ifdef DEBUG_PBE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBE FAILURE: Failed to get password data");
        }
#endif
        throwOCKException(env, 0, "Failed to get password data");
        goto cleanup;
    }
    passwordLength = (*env)->GetArrayLength(env, password);

    /*
     * Get the input data. 
     * Check for null is not required, a padded ouput is expected 
     * for null input data for algorithms with PKCS5Padding.
     */
    inputNative = (*env)->GetPrimitiveArrayCritical(env, input, &isCopy);
    inputLength = (*env)->GetArrayLength(env, input);

    // Perform encryption/decryption.
    resultNative = ICC_PKCS12_pbe_crypt(ockCtx, algor, passwordNative,
                                        passwordLength, inputNative,
                                        inputLength, NULL, &dataLength, is_en);
    if (NULL == resultNative) {
#ifdef DEBUG_PBE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBE FAILURE: Failed to encrypt/decrypt data");
        }
#endif
        throwOCKException(env, 0, "Failed to encrypt/decrypt data");
        goto cleanup;
    }

    // Allocate the result.
    resultText = (*env)->NewByteArray(env, dataLength);
    (*env)->SetByteArrayRegion(env, resultText, 0, dataLength,
                               (jbyte*)resultNative);

cleanup:
    if (NULL != text) {
        (*env)->ReleaseStringUTFChars(env, algorithm, text);
        text = NULL;
    }
    if (NULL != saltNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, salt, saltNative, 0);
        saltNative = NULL;
    }
    if (NULL != passwordNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, password,
                                              (void*)passwordNative, 0);
        passwordNative = NULL;
    }
    if (NULL != inputNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
        inputNative = NULL;
    }
    if (NULL != algor) {
        ICC_X509_ALGOR_free(ockCtx, algor);
        algor = NULL;
    }
    if (NULL != resultNative) {
        ICC_CRYPTO_free(ockCtx, resultNative);
        resultNative = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return resultText;
}
