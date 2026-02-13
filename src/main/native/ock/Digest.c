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
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_base_NativeInterface.h"
#include "Utils.h"
#include "Digest.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1create(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring digestAlgo) {
    static const char *functionName = "NativeInterface.DIGEST_create";

    ICC_CTX    *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest  *ockDigest       = (OCKDigest *)malloc(sizeof(OCKDigest));
    const char *digestAlgoChars = NULL;
    jlong       digestId        = 0;
    int         rc              = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (digestAlgo == NULL) {
        throwOCKException(env, 0,
                          "Digest create failed. The specified digest "
                          "algorithm is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return digestId;
    }
    if (ockDigest == NULL) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DIGEST FAILURE malloc of OCKDigest failed");
        }
#endif
        throwOCKException(env, 0, "Error allocating OCKDigest");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    } else {
        ockDigest->md    = NULL;
        ockDigest->mdCtx = NULL;
    }

    if (!(digestAlgoChars = (*env)->GetStringUTFChars(env, digestAlgo, NULL))) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DIGEST FAILURE digestAlgoChars failed");
        }
#endif
        throwOCKException(env, 0, "GetStringUTFChars() failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        if (ockDigest != NULL) {
            free(ockDigest);
            ockDigest = NULL;
        }
        return 0;
    }
#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST digestAlgorithm=%s", digestAlgoChars);
    }
#endif
    ockDigest->md = ICC_EVP_get_digestbyname(ockCtx, digestAlgoChars);
    if (NULL == ockDigest->md) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_DIGEST FAILURE JG_DEBUG ICC_EVP_get_digestbyname "
                "failed");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_get_digestbyname failed");
    } else {
        ockDigest->mdCtx = ICC_EVP_MD_CTX_new(ockCtx);
        if (NULL == ockDigest->mdCtx) {
#ifdef DEBUG_DIGEST_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DIGEST FAILURE ICC_EVP_MD_CTX_new failed");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_MD_CTX_new failed");
        } else {
            ICC_EVP_MD_CTX_init(ockCtx, ockDigest->mdCtx);

            rc = ICC_EVP_DigestInit(ockCtx, ockDigest->mdCtx, ockDigest->md);
            if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_DIGEST_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_DIGEST FAILURE ICC_EVP_DigestInit failed");
                }
#endif
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_EVP_DigestInit failed");
                if (ockDigest->mdCtx != NULL) {
                    rc = ICC_EVP_MD_CTX_free(ockCtx, ockDigest->mdCtx);
                    ockDigest->mdCtx = NULL;
                }
                ockCheckStatus(ockCtx);
            } else {
                digestId = (jlong)((intptr_t)ockDigest);
#ifdef DEBUG_DIGEST_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_DIGEST digestId=%lx ockDigest->mdCtx=%lx "
                        "ockDigest->md=%lx",
                        (long)digestId, ockDigest->mdCtx, ockDigest->md);
                }
#endif
            }
        }
    }

    (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);

    if (digestId == 0) {
        FREE_N_NULL(ockDigest);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return digestId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_copy
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1copy(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId) {
    static const char *functionName = "NativeInterface.DIGEST_copy";

    ICC_CTX   *ockCtx        = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest *ockDigest     = (OCKDigest *)((intptr_t)digestId);
    OCKDigest *ockDigestCopy = (OCKDigest *)malloc(sizeof(OCKDigest));
    jlong      digestCopyId  = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockDigest == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST ockDigest->mdCtx=%lx digestId %lx : ",
                     ockDigest->mdCtx, (long)digestId);
    }
#endif
    if (ockDigestCopy == NULL) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_DIGEST FAILURE malloc of copy of OCKDigest failed");
        }
#endif
        throwOCKException(env, 0, "Error allocating copy of OCKDigest");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    } else {
        ockDigestCopy->md    = ockDigest->md;
        ockDigestCopy->mdCtx = ICC_EVP_MD_CTX_new(ockCtx);
        if (NULL == ockDigestCopy->mdCtx) {
#ifdef DEBUG_DIGEST_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DIGEST FAILURE ICC_EVP_MD_CTX_new failed");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_MD_CTX_new failed");
        } else {
            if (ICC_OSSL_SUCCESS != ICC_EVP_MD_CTX_copy(ockCtx,
                                                        ockDigestCopy->mdCtx,
                                                        ockDigest->mdCtx)) {
#ifdef DEBUG_DIGEST_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_DIGEST FAILURE ICC_EVP_MD_CTX_copy failed");
                }
#endif
                throwOCKException(env, 0, "ICC_EVP_MD_CTX_copy failed");
            } else {
                digestCopyId = (jlong)((intptr_t)ockDigestCopy);
#ifdef DEBUG_DIGEST_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_DIGEST digestCopyId=%lx "
                        "ockDigestCopy->mdCtx=%lx ockDigest->md=%lx",
                        (long)digestCopyId, ockDigestCopy->mdCtx,
                        ockDigestCopy->md);
                }
#endif
            }
        }
    }

    if (digestCopyId == 0) {
        FREE_N_NULL(ockDigestCopy);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return digestCopyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_update
 * Signature: (JJ[BII)V
 */
JNIEXPORT int DIGEST_update_internal(ICC_CTX *ockCtx, OCKDigest *ockDigest,
                                     unsigned char *dataNative, int dataLen) {
    int                rc           = ICC_OSSL_SUCCESS;
    static const char *functionName = "NativeInterface.DIGEST_update";
    if ((ockDigest == NULL) || (dataNative == NULL) || (dataLen < 0) ||
        (ockDigest->mdCtx == NULL)) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_DIGEST_UPDATE;
    }
    rc = ICC_EVP_DigestUpdate(ockCtx, ockDigest->mdCtx, dataNative, dataLen);
    if (ICC_OSSL_SUCCESS != rc) {
        return FAIL_DIGEST_UPDATE;
    }
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1update(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId,
    jbyteArray data, jint offset, jint dataLen) {
    static const char *functionName = "NativeInterface.DIGEST_update";

    ICC_CTX       *ockCtx       = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest     *ockDigest    = (OCKDigest *)((intptr_t)digestId);
    unsigned char *dataNative   = NULL;
    jboolean       isCopy       = 0;
    int            returnResult = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockDigest == NULL) || (data == NULL) || (offset < 0)) {
        throwOCKException(env, 0,
                          "Digest Update failed. The specified input "
                          "parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jint)returnResult;
    }
    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data,
                                                                     &isCopy));
    if (NULL == dataNative) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DIGEST FAILURE ICC_EVP_DigestInit failed");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_DIGEST %d bytes to update offset %d: ",
                               (int)dataLen, (int)offset);
            gslogMessageHex((char *)dataNative + offset, 0, (int)dataLen, 0, 0,
                            NULL);
        }
#endif

#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DIGEST digestId=%lx ockDigest->mdCtx=%lx ",
                         (long)digestId, ockDigest->mdCtx);
        }
#endif
        returnResult = DIGEST_update_internal(
            ockCtx, ockDigest, dataNative + offset, (int)dataLen);
        if (DIGEST_INTERNAL_SUCCESS > returnResult) {
#ifdef DEBUG_DIGEST_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_DIGEST FAILURE ICC_EVP_DigestUpdate failed");
            }
#endif
            ockCheckStatus(ockCtx);
        }
    }

    if (dataNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_updateFastJNI
 * Signature: (JJJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1updateFastJNI(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId,
    jlong dataBuffer, jint dataLen) {
    static const char *functionName = "NativeInterface.DIGEST_updateFastJNI";

    ICC_CTX   *ockCtx     = (ICC_CTX *)ockContextId;
    OCKDigest *ockDigest  = (OCKDigest *)digestId;
    char      *dataNative = (char *)dataBuffer;
    int        rc         = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockDigest == NULL) || (dataNative == NULL) || (dataLen < 0)) {
        throwOCKException(env, 0,
                          "Digest update failed. The specified input "
                          "parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
#ifdef DEBUG_DIGEST_DATA
    if (debug) {
        gslogMessagePrefix("%d bytes to update : ", (int)dataLen);
        gslogMessageHex(dataNative, 0, (int)dataLen, 0, 0, NULL);
    }
#endif

    rc = ICC_EVP_DigestUpdate(ockCtx, ockDigest->mdCtx, dataNative,
                              (int)dataLen);
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_DigestUpdate failed");
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_digest
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1digest(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId) {
    static const char *functionName = "NativeInterface.DIGEST_digest";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest     *ockDigest         = (OCKDigest *)((intptr_t)digestId);
    jbyteArray     digestBytes       = NULL;
    unsigned char *digestBytesNative = NULL;
    jboolean       isCopy            = 0;
    int            digestLen         = 0;
    int            rc                = ICC_OSSL_SUCCESS;
    jbyteArray     retDigestBytes    = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockDigest == NULL) {
        throwOCKException(env, 0,
                          "Digest digest failed. The specified Digest "
                          "identifier is incorrect.");
    }
    digestLen = ICC_EVP_MD_size(ockCtx, ockDigest->md);
    if (digestLen <= 0) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DIGEST FAILURE ICC_EVP_MD_size failed");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_MD_size failed");
    } else {
        digestBytes = (*env)->NewByteArray(env, digestLen);
        if (digestBytes == NULL) {
#ifdef DEBUG_DIGEST_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_DIGEST FAILURE Failed to allocate digestBytes");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            digestBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, digestBytes, &isCopy));
            if (digestBytesNative == NULL) {
#ifdef DEBUG_DIGEST_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_DIGEST FAILURE Failed to allocate "
                        "digestBytesNative");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                rc = ICC_EVP_DigestFinal(ockCtx, ockDigest->mdCtx,
                                         digestBytesNative,
                                         (unsigned int *)&digestLen);
                if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_DIGEST_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DIGEST FAILURE ICC_EVP_DigestFinal failed");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_EVP_DigestFinal failed");
                } else {
                    retDigestBytes = digestBytes;
#ifdef DEBUG_DIGEST_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_DIGEST ockDigest->mdCtx %lx : ",
                                     ockDigest->mdCtx);
                        gslogMessagePrefix("DETAIL_DIGEST DigestLen %d : ",
                                           (int)digestLen);
                        gslogMessageHex((char *)digestBytes, 0, (int)digestLen,
                                        0, 0, NULL);
                    }
#endif
                }
            }
        }
    }

    if (digestBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, digestBytes,
                                              digestBytesNative, 0);
    }

    if ((digestBytes != NULL) && (retDigestBytes == NULL)) {
        (*env)->DeleteLocalRef(env, digestBytes);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retDigestBytes;
}

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_digest_and_reset
 * Signature: (JJJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1digest_1and_1reset__JJJI(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId,
    jlong digestBytes, jint length) {
    static const char *functionName = "NativeInterface.DIGEST_digest_and_reset";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest     *ockDigest         = (OCKDigest *)((intptr_t)digestId);
    unsigned char *digestBytesNative = (unsigned char *)((intptr_t)digestBytes);
    unsigned int   digestLen         = (unsigned int)length;
    int            rc                = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockDigest == NULL) || (digestBytesNative == NULL) || (length < 0) ||
        (ockDigest->mdCtx == NULL)) {
        throwOCKException(env, 0,
                          "Digest reset failed. The specified Digest "
                          "identifier or the digest bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
    rc = ICC_EVP_DigestFinal(ockCtx, ockDigest->mdCtx, digestBytesNative,
                             &digestLen);
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_DigestFinal failed");
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }

    /* digest reset */

    rc = ICC_EVP_DigestInit(ockCtx, ockDigest->mdCtx, ockDigest->md);
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_DigestInit failed");
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_digest_and_reset
 * Signature: (JJ[B)V
 */
JNIEXPORT int DIGEST_digest_and_reset_internal(
    ICC_CTX *ockCtx, OCKDigest *ockDigest, unsigned char *digestBytesNative) {
    int                rc = ICC_OSSL_SUCCESS;
    static const char *functionName =
        "NativeInterface.DIGEST_digest_and_reset_internal";
    if ((ockDigest == NULL) || (digestBytesNative == NULL)) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return FAIL_DIGEST_INIT;
    }
    rc = ICC_EVP_DigestFinal(ockCtx, ockDigest->mdCtx, digestBytesNative, NULL);
    if (ICC_OSSL_SUCCESS != rc) {
        return FAIL_DIGEST_FINAL;
    }
    rc = ICC_EVP_DigestInit(ockCtx, ockDigest->mdCtx, ockDigest->md);
    if (ICC_OSSL_SUCCESS != rc) {
        return FAIL_DIGEST_INIT;
    }
    return rc;
}

JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1digest_1and_1reset__JJ_3B(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId,
    jbyteArray digestBytes) {
    static const char *functionName = "NativeInterface.DIGEST_digest_and_reset";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest     *ockDigest         = (OCKDigest *)((intptr_t)digestId);
    unsigned char *digestBytesNative = NULL;
    jboolean       isCopy            = 0;
    int            returnResult      = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockDigest == NULL) || (digestBytes == NULL)) {
        throwOCKException(env, 0,
                          "Digest reset failed. The specified Digest identfier "
                          "or the digest bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return returnResult;
    }

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, digestBytes, &isCopy));
    if (digestBytesNative == NULL) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
    } else {
        returnResult = DIGEST_digest_and_reset_internal(ockCtx, ockDigest,
                                                        digestBytesNative);
        if (DIGEST_INTERNAL_SUCCESS > returnResult) {
            ockCheckStatus(ockCtx);
        }
    }

    if (digestBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, digestBytes,
                                              digestBytesNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jint)returnResult;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_size
 * Signature: (JJ)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1size(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId) {
    static const char *functionName = "NativeInterface.DIGEST_size";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest *ockDigest = (OCKDigest *)((intptr_t)digestId);
    int        digestLen = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockDigest == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        throwOCKException(env, 0,
                          "Digest size calculation failed. The specified "
                          "Digest identifier is incorrect.");
    } else if (ockDigest->md == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        throwOCKException(env, 0,
                          "Digest size calculation failed. The specified "
                          "Digest is incorrect.");
    } else {
        digestLen = ICC_EVP_MD_size(ockCtx, ockDigest->md);
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST ockDigest->md=%lx digestLen %d: ",
                     ockDigest->md, (int)digestLen);
    }
#endif
    if (debug) {
        gslogFunctionExit(functionName);
    }

    return digestLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_reset
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1reset(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId) {
    static const char *functionName = "NativeInterface.DIGEST_reset";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest *ockDigest = (OCKDigest *)((intptr_t)digestId);
    int        rc        = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockDigest == NULL) {
        throwOCKException(env, 0,
                          "Digest init operation failed. The specified Digest "
                          "identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_DIGEST ockDigest->mdCtx=%lx digestId %lx ockDigest->md=%lx "
            ": ",
            ockDigest->mdCtx, (long)digestId, ockDigest->md);
    }
#endif

    rc = ICC_EVP_DigestInit(ockCtx, ockDigest->mdCtx, ockDigest->md);
    if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DIGEST FAILURE ICC_EVP_DigestInit failed");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_DigestInit failed");
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DIGEST_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId) {
    static const char *functionName = "NativeInterface.DIGEST_delete";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest *ockDigest = (OCKDigest *)((intptr_t)digestId);
    int        rc        = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockDigest == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DIGEST ockDigest->mdCtx=%lx digestId %lx : ",
                     ockDigest->mdCtx, (long)digestId);
    }
#endif
    if (ockDigest->mdCtx != NULL) {
        rc               = ICC_EVP_MD_CTX_free(ockCtx, ockDigest->mdCtx);
        ockDigest->mdCtx = NULL;
        if (rc != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_DIGEST_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_DIGEST FAILURE ICC_EVP_MD_CTX_free failed rc %d",
                    rc);
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_MD_CTX_free failed!\n");
        }
    }
    if (ockDigest != NULL) {
        free(ockDigest);
        ockDigest = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    DIGEST_PKCS12KeyDeriveHelp
 * Signature: (JJ[BIII)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DIGEST_1PKCS12KeyDeriveHelp(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId,
    jbyteArray data, jint offset, jint dataLen, jint iterationCount) {
    ICC_CTX       *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest     *ockDigest = (OCKDigest *)((intptr_t)digestId);
    jboolean       isCopy    = 0;
    unsigned char *dataNative =
        (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, data, &isCopy);
    int retCode = 0;

    for (int i = 1; i < iterationCount; i++) {
        retCode = DIGEST_update_internal(ockCtx, ockDigest, dataNative + offset,
                                         (int)dataLen);
        if (retCode < 0) {
            throwOCKException(env, 0,
                              "Digest Update failed. The specified input "
                              "parameters are incorrect.");
            goto cleanup;
        }

        retCode =
            DIGEST_digest_and_reset_internal(ockCtx, ockDigest, dataNative);
        if (retCode < 0) {
            throwOCKException(env, 0,
                              "Digest and Reset failed. The specified input "
                              "parameters are incorrect.");
            goto cleanup;
        }
    }

cleanup:
    if (NULL != dataNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, 0);
        dataNative = NULL;
    }

    return retCode;
}
