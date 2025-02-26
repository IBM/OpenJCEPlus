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
 * Method:    PBKDF2_derive
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_PBKDF2_1derive(
    JNIEnv *env, jclass thisObj, jlong contextId, jstring hashAlgorithm,
    jbyteArray password, jbyteArray salt, jint iterations, jint keyLength) {
    static const char *functionName       = "NativeInterface.PBKDF2_derive";
    ICC_CTX           *ockCtx             = (ICC_CTX *)((intptr_t)contextId);
    const char        *hashAlgorithmChars = NULL;
    unsigned char     *saltNative         = NULL;
    const char        *passwordNative     = NULL;
    const ICC_EVP_MD  *messageDigest      = NULL;
    jbyteArray         resultDerivedKey   = NULL;
    unsigned char     *resultDerivedKeyNative = NULL;
    jboolean           isCopy                 = 0;
    int                saltLength             = 0;
    int                passwordLength         = 0;
    int                rc                     = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    // Validation is assumed by the caller for the key length input,
    // context, algorithm, and password.

    // Get the hash algorithm name.
    hashAlgorithmChars = (*env)->GetStringUTFChars(env, hashAlgorithm, NULL);
    if (NULL == hashAlgorithmChars) {
#ifdef DEBUG_PBKDF_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_PBKDF FAILURE: Failed to get hash algorithm name");
        }
#endif
        throwOCKException(env, 0, "Failed to get hash algorithm name");
        goto cleanup;
    }

    // Get the salt.
    saltNative = (*env)->GetPrimitiveArrayCritical(env, salt, &isCopy);
    if (NULL == saltNative) {
#ifdef DEBUG_PBKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBKDF FAILURE: Failed to get salt");
        }
#endif
        throwOCKException(env, 0, "Failed to get salt");
        goto cleanup;
    }
    saltLength = (*env)->GetArrayLength(env, salt);

    // Get the password.
    passwordNative = (*env)->GetPrimitiveArrayCritical(env, password, &isCopy);
    if (NULL == passwordNative) {
#ifdef DEBUG_PBKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBKDF FAILURE: Failed to get password data");
        }
#endif
        throwOCKException(env, 0, "Failed to get password data");
        goto cleanup;
    }
    passwordLength = (*env)->GetArrayLength(env, password);

    // Get the message digest specified by hashAlgorithmChars.
    messageDigest = ICC_EVP_get_digestbyname(ockCtx, hashAlgorithmChars);
    if (NULL == messageDigest) {
#ifdef DEBUG_PBKDF_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_PBKDF FAILURE: Failed to initialize hash function");
        }
#endif
        throwOCKException(env, 0, "Failed to initialize hash function");
        goto cleanup;
    }

    // Allocate the result.
    resultDerivedKey = (*env)->NewByteArray(env, keyLength);
    if (NULL == resultDerivedKey) {
#ifdef DEBUG_PBKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBKDF FAILURE: Failed to create result array");
        }
#endif
        throwOCKException(env, 0, "Failed to create result array");
        goto cleanup;
    }

    // Get pointer to result we just allocated.
    resultDerivedKeyNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, resultDerivedKey, &isCopy));
    if (NULL == resultDerivedKeyNative) {
#ifdef DEBUG_PBKDF_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_PBKDF FAILURE: Failed to get native derived key");
        }
#endif
        throwOCKException(env, 0, "Failed to get native derived key");
        goto cleanup;
    }

    // Execute PBKDF2 key derivation
    rc = ICC_PKCS5_PBKDF2_HMAC(
        ockCtx, passwordNative, passwordLength, saltNative, saltLength,
        iterations, messageDigest, keyLength, resultDerivedKeyNative);
    if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_PBKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_PBKDF FAILURE: Key derivation failed");
        }
#endif
        throwOCKException(env, 0, "Key derivation failed");
        goto cleanup;
    }

// Release all necessary resources.
cleanup:
    if (NULL != resultDerivedKeyNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, resultDerivedKey,
                                              resultDerivedKeyNative, 0);
        resultDerivedKeyNative = NULL;
    }
    if (NULL != passwordNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, password,
                                              (void *)passwordNative, 0);
        passwordNative = NULL;
    }
    if (NULL != saltNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, salt, saltNative, 0);
        saltNative = NULL;
    }
    if (NULL != hashAlgorithmChars) {
        (*env)->ReleaseStringUTFChars(env, hashAlgorithm, hashAlgorithmChars);
        hashAlgorithmChars = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return resultDerivedKey;
}
