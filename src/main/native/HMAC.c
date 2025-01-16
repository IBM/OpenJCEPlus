/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include <stdbool.h>
#ifdef __MVS__
#define bool _Bool
#endif

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

#define JNI_FALSE 0
#define JNI_TRUE 1

typedef struct OCKHMAC {
    ICC_HMAC_CTX     *hmacCtx;
    const ICC_EVP_MD *md;
} OCKHMAC;

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HMAC_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HMAC_1create(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring digestAlgo) {
    static const char *functionName = "NativeInterface.HMAC_create";

    ICC_CTX    *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHMAC    *ockHMAC         = (OCKHMAC *)malloc(sizeof(OCKHMAC));
    const char *digestAlgoChars = NULL;
    jlong       hmacId          = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockHMAC == NULL) {
        throwOCKException(env, 0, "Error allocating OCKHMAC");
        if (debug) {
#ifdef DEBUG_HMAC_DETAIL
            gslogMessage("DETAIL_HMAC FAILURE: Unable to allocate OCKHMAC");
#endif
            gslogFunctionExit(functionName);
        }
        return 0;
    } else {
        ockHMAC->hmacCtx = NULL;
        ockHMAC->md      = NULL;
    }

    if (!(digestAlgoChars = (*env)->GetStringUTFChars(env, digestAlgo, NULL))) {
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC FAILURE: digestAlgoChars");
        }
#endif
        throwOCKException(env, 0, "GetStringUTFChars() failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        FREE_N_NULL(ockHMAC);
        return 0;
    }

    if (debug) {
        gslogMessage("DATA_HMAC digestAlgo=%s", digestAlgoChars);
    }

    ockHMAC->md = ICC_EVP_get_digestbyname(ockCtx, digestAlgoChars);
    if (NULL == ockHMAC->md) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC FAILURE ICC_EVP_get_digestbyname");
        }
#endif
        throwOCKException(env, 0, "ICC_EVP_get_digestbyname failed");
    } else {
        ockHMAC->hmacCtx = ICC_HMAC_CTX_new(ockCtx);
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC ockHMAC->hmacCtx : %lx",
                         ockHMAC->hmacCtx);
        }
#endif
        if (NULL == ockHMAC->hmacCtx) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_HMAC_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HMAC FAILURE to create ockHMAC->hmacCtx ");
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_HMAC_CTX_new failed");
        } else {
            hmacId = (jlong)((intptr_t)ockHMAC);

#ifdef DEBUG_HMAC_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HMAC hmacId : %lx", hmacId);
            }
#endif
        }
    }

    (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);

    // If an error occurred, free up the OCKHMAC allocation
    //
    if (hmacId == 0 && (ockHMAC != NULL)) {
        free(ockHMAC);
        ockHMAC = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return hmacId;
}

/* init internal function */

int HMAC_init_internal(ICC_CTX *ockCtx, OCKHMAC *ockHMAC,
                       unsigned char *keyNative, int keySize) {
    int                rc           = ICC_OSSL_SUCCESS;
    static const char *functionName = "NativeInterface.HMAC_init_internal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC ockHMAC : %lx ", ockHMAC);
        if (NULL != ockHMAC) {
            gslogMessage("DETAIL_HMAC ockHMAC->hmacCtx : %lx ockHMAC->md %lx",
                         ockHMAC->hmacCtx, ockHMAC->md);
        }
    }
#endif
    if ((ockHMAC == NULL) || (keyNative == NULL)) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_INIT;
    } else if ((ockHMAC->hmacCtx == NULL) || (ockHMAC->md == NULL)) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_INIT;
    }
    rc = ICC_HMAC_Init(ockCtx, ockHMAC->hmacCtx, keyNative, keySize,
                       ockHMAC->md);
#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC keysize : %d rc %d from ICC_HMAC_Init",
                     (int)keySize, rc);
    }
#endif
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC ICC_HMAC_Init rc %d", rc);
        }
#endif
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_INIT;
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }
    return HMAC_INTERNAL_SUCCESS;
}

/*
 * This is a local function used in HMAC.c
 * It is called by method HMAC_update and HMAC_doFinal when an object have not
 * been initialized.
 */
int HMAC_init(JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hmacId,
              jbyteArray key, jint keySize) {
    static const char *functionName = "NativeInterface.HMAC_init";

    ICC_CTX       *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHMAC       *ockHMAC   = (OCKHMAC *)((intptr_t)hmacId);
    unsigned char *keyNative = NULL;
    jboolean       isCopy    = 0;
    int            result    = HMAC_INTERNAL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC hmacId : %lx", (long)hmacId);
    }
#endif
    if (ockHMAC == NULL) {
        throwOCKException(env, 0,
                          "The specified HMAC Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_INIT;
    } else if (key == NULL) {
        throwOCKException(env, 0, "The specified Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_INIT;
    }
    keyNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));
    if (NULL == keyNative) {
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC FAILURE to allocate keyNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    }

    result = HMAC_init_internal(ockCtx, ockHMAC, keyNative, keySize);

    if (keyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
    return result;
}

/* update internal */
JNIEXPORT int HMAC_update_internal(ICC_CTX *ockCtx, OCKHMAC *ockHMAC,
                                   unsigned char *keyNative, int keySize,
                                   unsigned char *inputNative, int inputLen,
                                   bool needInit) {
    int                result       = HMAC_INTERNAL_SUCCESS;
    int                rc           = ICC_OSSL_SUCCESS;
    static const char *functionName = "NativeInterface.HAMC_update_internal";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockHMAC == NULL) || (keyNative == NULL) || (inputNative == NULL)) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_UPDATE;
    }
    if (needInit == JNI_TRUE) {
        result = HMAC_init_internal(ockCtx, ockHMAC, keyNative, keySize);
        if (HMAC_INTERNAL_SUCCESS != result) {
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return result;
        }
    }

#ifdef DEBUG_HMAC_DATA
    if (debug) {
        gslogMessagePrefix("DATA_HMAC %d bytes to update : ", (int)inputLen);
        gslogMessageHex((char *)inputNative, 0, (int)inputLen, 0, 0, NULL);
    }
#endif

#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC ockHMAC : %lx ", ockHMAC);
        if (NULL != ockHMAC) {
            gslogMessage("DETAIL_HMAC ockHMAC->hmacCtx : %lx ",
                         ockHMAC->hmacCtx);
        }
    }
#endif
    if (ockHMAC->hmacCtx == NULL) {
        result = FAIL_HMAC_INTERNAL_UPDATE;
    } else {
        rc = ICC_HMAC_Update(ockCtx, ockHMAC->hmacCtx, inputNative,
                             (int)inputLen);
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC rc from ICC_HMAC_Update %d", rc);
        }
#endif
        if (ICC_OSSL_SUCCESS != rc) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_HMAC_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HMAC FAILURE ICC_HMAC_Update failed");
            }
#endif
            result = FAIL_HMAC_INTERNAL_UPDATE;
        }
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }
    return result;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HMAC_update
 * Signature: (JJ[BII)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HMAC_1update(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hmacId,
    jbyteArray key, jint keyLength, jbyteArray input, jint inputOffset,
    jint inputLen, jboolean needInit) {
    static const char *functionName = "NativeInterface.HMAC_update";

    ICC_CTX       *ockCtx      = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHMAC       *ockHMAC     = (OCKHMAC *)((intptr_t)hmacId);
    unsigned char *inputNative = NULL;
    unsigned char *keyNative   = NULL;
    jboolean       isCopy      = 0;
    int            result      = HMAC_INTERNAL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockHMAC == NULL) || (key == NULL) || (keyLength <= 0) ||
        (input == NULL)) {
        throwOCKException(env, 0, "The specified parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_UPDATE;
    }
#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC hmacId : %lx inputLen %d inputOffset %d",
                     (long)hmacId, (int)inputLen, inputOffset);
    }
#endif
    inputNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, input, &isCopy));
    keyNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));
    if (NULL == inputNative || NULL == keyNative) {
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            if (NULL == inputNative) {
                gslogMessage("DETAIL_HMAC FAILURE to allocate inputNative");
            }
            if (NULL == keyNative) {
                gslogMessage("DETAIL_HMAC FAILURE to allocate keyNative");
            }
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        result =
            HMAC_update_internal(ockCtx, ockHMAC, keyNative, keyLength,
                                 inputNative + inputOffset, inputLen, needInit);
    }
    if (inputNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, input, inputNative, 0);
    }
    if (NULL != keyNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
    return result;
}

JNIEXPORT int HMAC_doFinal_internal(ICC_CTX *ockCtx, OCKHMAC *ockHMAC,
                                    unsigned char *keyNative, int keySize,
                                    unsigned char *hmac, bool needInit) {
    static const char *functionName = "NativeInterface.HMAC_doFinal_internal";

    unsigned int hmacLen = 0;
    int          rc      = ICC_OSSL_SUCCESS;
    int          result  = HMAC_INTERNAL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockHMAC == NULL) || (keyNative == NULL) || (hmac == NULL)) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_DOFINAL;
    }
    if (needInit == JNI_TRUE) {
        result = HMAC_init_internal(ockCtx, ockHMAC, keyNative, keySize);
        if (HMAC_INTERNAL_SUCCESS != result) {
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return result;
        }
    }
    if (ockHMAC->hmacCtx == NULL) {
        result = FAIL_HMAC_INTERNAL_DOFINAL;
    } else {
        rc = ICC_HMAC_Final(ockCtx, ockHMAC->hmacCtx, hmac, &hmacLen);

        if (ICC_OSSL_SUCCESS != rc) {
            ockCheckStatus(ockCtx);
            result = FAIL_HMAC_INTERNAL_DOFINAL;
#ifdef DEBUG_HMAC_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HMAC FAILURE ICC_HMAC_Final failed rc %d",
                             rc);
            }
#endif
        }
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }
    return result;
}
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HMAC_doFinal
 * Signature: (JJ)[B
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HMAC_1doFinal(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hmacId,
    jbyteArray key, jint keyLength, jbyteArray hmac, jboolean needInit) {
    static const char *functionName = "NativeInterface.HMAC_doFinal";

    ICC_CTX *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHMAC *ockHMAC = (OCKHMAC *)((intptr_t)hmacId);

    unsigned char *keyNative = NULL;

    jboolean       isCopy     = 0;
    unsigned char *hmacNative = NULL;

    int result = HMAC_INTERNAL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockHMAC == NULL) || (key == NULL) || (keyLength <= 0) ||
        (hmac == NULL)) {
        throwOCKException(env, 0, "The specified parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_DOFINAL;
    }
    keyNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));
    if (NULL == keyNative) {
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC FAILURE to allocate keyNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_HMAC_INTERNAL_DOFINAL;
    }

    hmacNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, hmac,
                                                                     &isCopy));
    if (hmacNative == NULL) {
#ifdef DEBUG_HMAC_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HMAC FAILURE to allocate hmacNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
    } else {
        result = HMAC_doFinal_internal(ockCtx, ockHMAC, keyNative, keyLength,
                                       hmacNative, needInit);
    }
    if (keyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }
    if (hmacNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, hmac, hmacNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return result;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HMAC_size
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HMAC_1size(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hmacId) {
    static const char *functionName = "NativeInterface.HMAC_size";

    ICC_CTX *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHMAC *ockHMAC   = (OCKHMAC *)((intptr_t)hmacId);
    int      digestLen = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC hmacId : %lx ", (long)hmacId);
        if (ockHMAC != NULL) {
            gslogMessage("DETAIL_HMAC ockHMAC->md : %lx ", ockHMAC->md);
        }
    }
#endif
    if (ockHMAC == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return digestLen;
    } else if (ockHMAC->md == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return digestLen;
    }
    digestLen = ICC_EVP_MD_size(ockCtx, ockHMAC->md);
#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC digestLen : %ld ", (int)digestLen);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return digestLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HMAC_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HMAC_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hmacId) {
    static const char *functionName = "NativeInterface.HMAC_delete";

    ICC_CTX *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHMAC *ockHMAC = (OCKHMAC *)((intptr_t)hmacId);

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockHMAC == NULL) {
        // No cleaning is not needed
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
#ifdef DEBUG_HMAC_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HMAC hmacId : %lx ", (long)hmacId);
        gslogMessage("DETAIL_HMAC ockHMAC->hmacCtx : %lx ", ockHMAC->hmacCtx);
    }

#endif
    if ((ockHMAC->hmacCtx) != NULL) {
        ICC_HMAC_CTX_free(ockCtx, ockHMAC->hmacCtx);
        ockHMAC->hmacCtx = NULL;
    }
    FREE_N_NULL(ockHMAC);
    if (debug) {
        gslogFunctionExit(functionName);
    }
}
