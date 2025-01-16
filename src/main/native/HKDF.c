/*
 * Copyright IBM Corp. 2023, 2024
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

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

typedef struct OCKHKDF {
    ICC_EVP_PKEY_CTX *pctx;
    const ICC_EVP_MD *md;
} OCKHKDF;

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HKDF_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HKDF_1create(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring digestAlgo) {
    static const char *functionName = "NativeInterface.HKDF_create";

    ICC_CTX    *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHKDF    *ockHKDF         = NULL;
    const char *digestAlgoChars = NULL;
    jlong       hkdfId          = 0;
#ifdef DEBUG_HKDF_DETAIL
    int nid = 0;
#endif
    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (digestAlgo == NULL) {
        throwOCKException(env, 0,
                          "The specified digest algorithm is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return hkdfId;
    }
    ockHKDF = (OCKHKDF *)malloc(sizeof(OCKHKDF));
    if (ockHKDF == NULL) {
        throwOCKException(env, 0, "Error allocating OCKHKDF");
        if (debug) {
#ifdef DEBUG_HKDF_DETAIL
            gslogMessage("DETAIL_HKDF FAILURE: Unable to allocate OCKHKDF");
#endif
            gslogFunctionExit(functionName);
        }
        return 0;
    } else {
        ockHKDF->pctx = NULL;
        ockHKDF->md   = NULL;
    }

    if (!(digestAlgoChars = (*env)->GetStringUTFChars(env, digestAlgo, NULL))) {
#ifdef DEBUG_HKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HKDF FAILURE: digestAlgoChars");
        }
#endif
        throwOCKException(env, 0, "GetStringUTFChars() failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        FREE_N_NULL(ockHKDF);
        return 0;
    }

    if (debug) {
        gslogMessage("DATA_HKDF digestAlgo=%s", digestAlgoChars);
    }

#ifdef DEBUG_HKDF_DETAIL
#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
    nid = ICC_OBJ_txt2nid(ockCtx, "HKDF");
#ifdef __MVS__
#pragma convert(pop)
#endif
    if (debug) {
        gslogMessage("DETAIL_HKDF nid=%d", nid);
    }
#endif

    ockHKDF->md = ICC_EVP_get_digestbyname(ockCtx, digestAlgoChars);
    if (NULL == ockHKDF->md) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_HKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HKDF FAILURE ICC_EVP_get_digestbyname");
        }
#endif
        throwOCKException(env, 0, "ICC_EVP_get_digestbyname failed");
    } else {
        hkdfId = (jlong)((intptr_t)ockHKDF);

#ifdef DEBUG_HKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HKDF hkdfId : %lx", hkdfId);
        }
#endif
    }

    (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);

    // If an error occurred, free up the OCKHKDF allocation
    //
    if (hkdfId == 0) {
        FREE_N_NULL(ockHKDF);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return hkdfId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HKDF_extract
 * Signature: (JJ[BII)V
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HKDF_1extract(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hkdfId,
    jbyteArray salt, jlong saltLenl, jbyteArray inKey, jlong inKeyLenl) {
    static const char *functionName = "NativeInterface.HKDF_extract";

    ICC_CTX       *ockCtx      = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHKDF       *ockHKDF     = (OCKHKDF *)((intptr_t)hkdfId);
    unsigned char *saltNative  = NULL;
    unsigned char *inKeyNative = NULL;
    jboolean       isCopy      = 0;

    unsigned char prkLocal[ICC_EVP_MAX_MD_SIZE];
    size_t        prkLen   = 0;
    size_t        saltLen  = (size_t)saltLenl;
    size_t        inKeyLen = (size_t)inKeyLenl;

    jbyteArray     prk       = NULL;
    unsigned char *prkNative = NULL;
    jbyteArray     retPrk    = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockHKDF == NULL) {
        throwOCKException(env, 0,
                          "The specified HKDF identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retPrk;
    }

#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_HKDFextract  hkdfId : %lx saltLen %ld inKeyLen %ld",
            (long)hkdfId, (long)saltLen, (long)inKeyLen);
    }
#endif

    saltNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, salt,
                                                                     &isCopy));
    if (NULL == saltNative) {
#ifdef DEBUG_HKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HKDF FAILURE to allocate saltNative");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        inKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, inKey, &isCopy));
        if (NULL == inKeyNative) {
#ifdef DEBUG_HKDF_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HKDF FAILURE to allocate inKeyNative");
            }
#endif
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        } else {
#ifdef DEBUG_HKDF_DATA
            if (debug) {
                gslogMessagePrefix("DATA_HKDF %d inKey bytes length  : ",
                                   (int)inKeyLen);
                gslogMessageHex((char *)inKeyNative, 0, (int)inKeyLen, 0, 0,
                                NULL);
                gslogMessagePrefix("DATA_HKDF %d salt bytes length  : ",
                                   (int)saltLen);
                gslogMessageHex((char *)saltNative, 0, (int)saltLen, 0, 0,
                                NULL);
            }
#endif

#ifdef DEBUG_HKDF_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HKDF ockHKDF : %lx ", ockHKDF);
                if (NULL != ockHKDF) {
                    gslogMessage("DETAIL_HKDF ockHKDF->pctx : %lx ",
                                 ockHKDF->pctx);
                }
            }
#endif
            ICC_HKDF_Extract(ockCtx, ockHKDF->md, saltNative, (int)saltLen,
                             inKeyNative, (int)inKeyLen, prkLocal, &prkLen);

#ifdef DEBUG_HKDF_DATA
            if (debug) {
                gslogMessage("DATA_HKDF Extract prkLen : %d ", prkLen);
                gslogMessagePrefix("DATA_HKDF Extracted Bytes : ");
                gslogMessageHex((char *)prkLocal, 0, prkLen, 0, 0, NULL);
            }
#endif
            prk = (*env)->NewByteArray(env, prkLen);
            if (prk == NULL) {
#ifdef DEBUG_HKDF_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_HKDF FAILURE to allocate prk(hkdf)");
                }
#endif
                throwOCKException(env, 0, "NewByteArray failed");
            } else {
                prkNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, prk, &isCopy));
                if (prkNative == NULL) {
#ifdef DEBUG_HKDF_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_HKDF FAILURE to allocate prkNative");
                    }
#endif
                    throwOCKException(env, 0,
                                      "NULL from GetPrimitiveArrayCritical");
                } else {
#ifdef DEBUG_HKDF_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_HKDF memcpy prkNative %lx prkLocal %lx "
                            "prkLen %d",
                            prkNative, prkLocal, prkLen);
                    }
#endif
                    memcpy(prkNative, prkLocal, prkLen);
                    retPrk = prk;
                }
            }
        } /* inKeyNative == NULL */
    } /* saltNative == NULL */

    if (inKeyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, inKey, inKeyNative, 0);
    }

    if (saltNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, salt, saltNative, 0);
    }

    if (prkNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, prk, prkNative, 0);
    }

    if ((prk != NULL) && (retPrk == NULL)) {
        (*env)->DeleteLocalRef(env, prk);
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retPrk;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HKDF_expand
 * Signature: (JJ[BII)V
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HKDF_1expand(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hkdfId,
    jbyteArray prk, jlong prkLenl, jbyteArray info, jlong infoLenl,
    jlong okmLenl) {
    static const char *functionName = "NativeInterface.HKDF_expand";

    ICC_CTX       *ockCtx     = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHKDF       *ockHKDF    = (OCKHKDF *)((intptr_t)hkdfId);
    unsigned char *prkNative  = NULL;
    unsigned char *infoNative = NULL;
    jboolean       isCopy     = 0;
    unsigned char *ptr        = NULL;

    unsigned char *okmLocal  = NULL;
    size_t         infoLen   = (size_t)infoLenl;
    size_t         prkLen    = (size_t)prkLenl;
    size_t         okmLen    = (size_t)okmLenl;
    unsigned char *okmNative = NULL;
    jbyteArray     okm       = NULL;
    jbyteArray     retOkm    = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockHKDF == NULL) || (prk == NULL) || (info == NULL)) {
        throwOCKException(env, 0,
                          "The specified HKDF identifiers are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retOkm;
    }
#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_HKDF hkdfId : %lx prkLen %ld infoLen %ld okmLen %ld",
            (long)hkdfId, (long)prkLen, (long)infoLen, (long)okmLen);
    }
#endif

    prkNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, prk, &isCopy));
    if (NULL == prkNative) {
#ifdef DEBUG_HKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HKDF FAILURE to allocate prkNative");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        infoNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, info, &isCopy));
        if (NULL == infoNative) {
#ifdef DEBUG_HKDF_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HKDF FAILURE to allocate infoNative");
            }
#endif
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        } else {
#ifdef DEBUG_HKDF_DATA
            if (debug) {
                gslogMessagePrefix("DATA_HKDF %ld info bytes length  : ",
                                   (long)infoLen);
                gslogMessageHex((char *)infoNative, 0, (long)infoLen, 0, 0,
                                NULL);
                gslogMessagePrefix("DATA_HKDF %ld prk bytes length  : ",
                                   (long)prkLen);
                gslogMessageHex((char *)prkNative, 0, (long)prkLen, 0, 0, NULL);
            }
#endif

#ifdef DEBUG_HKDF_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HKDF ockHKDF : %lx ", ockHKDF);
                if (NULL != ockHKDF) {
                    gslogMessage("DETAIL_HKDF ockHKDF->pctx : %lx ",
                                 ockHKDF->pctx);
                }
            }
#endif

            okmLocal = calloc(1, okmLen);

            ptr = (unsigned char *)ICC_HKDF_Expand(
                ockCtx, ockHKDF->md, prkNative, (int)prkLen, infoNative,
                infoLen, okmLocal, okmLen);
            if (ptr == NULL) {
                throwOCKException(env, 0, "ICC_HKDF_Expand failed");
            } else {
#ifdef DEBUG_HKDF_DATA
                if (debug) {
                    gslogMessage("DATA_HKDF Expand okmLen : %d ", okmLen);
                    gslogMessagePrefix("DATA_HKDF Expanded Bytes : ");
                    gslogMessageHex((char *)okmLocal, 0, okmLen, 0, 0, NULL);
                }
#endif
                okm = (*env)->NewByteArray(env, okmLen);
                if (okm == NULL) {
#ifdef DEBUG_HKDF_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_HKDF FAILURE to allocate okm (hkdf)");
                    }
#endif
                    throwOCKException(env, 0, "NewByteArray failed");
                } else {
                    okmNative =
                        (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                            env, okm, &isCopy));
                    if (okmNative == NULL) {
#ifdef DEBUG_HKDF_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_HKDF FAILURE to allocate okmNative");
                        }
#endif
                        throwOCKException(
                            env, 0, "NULL from GetPrimitiveArrayCritical");
                    } else {
#ifdef DEBUG_HKDF_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_HKDF memcpy okmNative %lx okmLocal %lx "
                                "okmLen %d",
                                okmNative, okmLocal, okmLen);
                        }
#endif
                        memcpy(okmNative, okmLocal, okmLen);
                        retOkm = okm;
                    }
                }
            }
        } /* infoNative == NULL */
    } /* prkNative == NULL */

    if (infoNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, info, infoNative, 0);
    }

    if (prkNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, prk, prkNative, 0);
    }

    FREE_N_NULL(okmLocal);

    if (okmNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, okm, okmNative, 0);
    }

    if ((okm != NULL) && (retOkm == NULL)) {
        (*env)->DeleteLocalRef(env, okm);
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retOkm;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HKDF_derive
 * Signature: (JJ[BII)V
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HKDF_1derive(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hkdfId,
    jbyteArray salt, jlong saltLenl, jbyteArray inKey, jlong inKeyLenl,
    jbyteArray info, jlong infoLenl, jlong resKeyLenl) {
    static const char *functionName = "NativeInterface.HKDF_1derive";

    ICC_CTX       *ockCtx       = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHKDF       *ockHKDF      = (OCKHKDF *)((intptr_t)hkdfId);
    unsigned char *saltNative   = NULL;
    unsigned char *inKeyNative  = NULL;
    unsigned char *infoNative   = NULL;
    jboolean       isCopy       = 0;
    unsigned char *ptr          = NULL;
    jbyteArray     resKey       = NULL;
    unsigned char *resKeyNative = NULL;
    jbyteArray     retResKey    = NULL;
    unsigned char *resKeyLocal  = NULL;
    size_t         saltLen      = (size_t)saltLenl;
    size_t         inKeyLen     = (size_t)inKeyLenl;
    size_t         infoLen      = (size_t)infoLenl;
    size_t         resKeyLen    = (size_t)resKeyLenl;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockHKDF == NULL) || (inKey == NULL)) {
        throwOCKException(
            env, 0,
            "The specified HKDF identifier or HKDF Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retResKey;
    }
#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_HKDFextract  hkdfId : %lx saltLen %ld inKeyLen %ld infoLen "
            "%ld resKeyLen %ld",
            (long)hkdfId, (long)saltLen, (long)inKeyLen, (long)infoLen,
            (long)resKeyLen);
    }
#endif

    saltNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, salt,
                                                                     &isCopy));
    if (NULL == saltNative) {
#ifdef DEBUG_HKDF_DETAIL
        if (debug) {
            gslogMessage("DETAIL_HKDF FAILURE to allocate saltNative");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        inKeyNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, inKey, &isCopy));
        if (NULL == inKeyNative) {
#ifdef DEBUG_HKDF_DETAIL
            if (debug) {
                gslogMessage("DETAIL_HKDF FAILURE to allocate inKeyNative");
            }
#endif
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        } else {
            infoNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                env, info, &isCopy));
            if (NULL == infoNative) {
#ifdef DEBUG_HKDF_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_HKDF FAILURE to allocate infoNative");
                }
#endif
                throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
            } else {
#ifdef DEBUG_HKDF_DATA
                if (debug) {
                    gslogMessagePrefix("DATA_HKDF %d inKey bytes length  : ",
                                       (int)inKeyLen);
                    gslogMessageHex((char *)inKeyNative, 0, (int)inKeyLen, 0, 0,
                                    NULL);
                    gslogMessagePrefix("DATA_HKDF %d salt bytes length  : ",
                                       (int)saltLen);
                    gslogMessageHex((char *)saltNative, 0, (int)saltLen, 0, 0,
                                    NULL);
                    gslogMessagePrefix("DATA_HKDF %d info bytes length  : ",
                                       (int)infoLen);
                    gslogMessageHex((char *)infoNative, 0, (int)infoLen, 0, 0,
                                    NULL);
                }
#endif

#ifdef DEBUG_HKDF_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_HKDF ockHKDF : %lx ", ockHKDF);
                    if (NULL != ockHKDF) {
                        gslogMessage("DETAIL_HKDF ockHKDF->pctx : %lx ",
                                     ockHKDF->pctx);
                    }
                }
#endif
                resKeyLocal = calloc(1, (long)resKeyLen);
                ptr = ICC_HKDF(ockCtx, ockHKDF->md, saltNative, (long)saltLen,
                               inKeyNative, (long)inKeyLen, infoNative,
                               (long)infoLen, resKeyLocal, resKeyLen);
                if (ptr == NULL) {
                    throwOCKException(env, 0, "ICC_HKDF failed");
                } else {
#ifdef DEBUG_HKDF_DATA
                    if (debug) {
                        gslogMessage("DATA_HKDF Derived resKeyLen : %ld ",
                                     (long)resKeyLen);
                        gslogMessagePrefix("DATA_HKDF Extracted Bytes : ");
                        gslogMessageHex((char *)resKeyLocal, 0, resKeyLen, 0, 0,
                                        NULL);
                    }
#endif
                    resKey = (*env)->NewByteArray(env, resKeyLen);
                    if (resKey == NULL) {
#ifdef DEBUG_HKDF_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_HKDF FAILURE to allocate resKey(hkdf)");
                        }
#endif
                        throwOCKException(env, 0, "NewByteArray failed");
                    } else {
                        resKeyNative =
                            (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                                env, resKey, &isCopy));
                        if (resKeyNative == NULL) {
#ifdef DEBUG_HKDF_DETAIL
                            if (debug) {
                                gslogMessage(
                                    "DETAIL_HKDF FAILURE to allocate "
                                    "prkNative");
                            }
#endif
                            throwOCKException(
                                env, 0, "NULL from GetPrimitiveArrayCritical");
                        } else {
#ifdef DEBUG_HKDF_DETAIL
                            if (debug) {
                                gslogMessage(
                                    "DETAIL_HKDF memcpy resKeyNative %lx "
                                    "resKeyLocal %lx resKeyLen %d",
                                    resKeyNative, resKeyLocal, resKeyLen);
                            }
#endif
                            memcpy(resKeyNative, resKeyLocal, resKeyLen);
                            retResKey = resKey;
                        }
                    }
                }
            } /*infoKeyNative == NULL */
        } /* inKeyNative == NULL */
    } /* saltNative == NULL */

    if (NULL != resKeyLocal) {
        free(resKeyLocal);
    }

    if (NULL != inKeyNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, inKey, inKeyNative, 0);
    }

    if (NULL != saltNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, salt, saltNative, 0);
    }

    if (NULL != infoNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, info, infoNative, 0);
    }

    if (NULL != resKeyNative) {
        (*env)->ReleasePrimitiveArrayCritical(env, resKey, resKeyNative, 0);
    }

    if ((NULL != resKey) && (NULL == retResKey)) {
        (*env)->DeleteLocalRef(env, resKey);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retResKey;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    HKDF_size
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HKDF_1size(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hkdfId) {
    static const char *functionName = "NativeInterface.Hkdf_size";

    ICC_CTX *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHKDF *ockHKDF   = (OCKHKDF *)((intptr_t)hkdfId);
    int      digestLen = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockHKDF == NULL) {
        throwOCKException(env, 0,
                          "The specified HKDF identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return digestLen;
    }
#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF hkdfId : %lx ", (long)hkdfId);
        if (ockHKDF != NULL) {
            gslogMessage("DETAIL_HKDF ockHKDF->md : %lx ", ockHKDF->md);
        }
    }
#endif

    digestLen = ICC_EVP_MD_size(ockCtx, ockHKDF->md);
#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF digestLen : %ld ", (int)digestLen);
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
 * Method:    HKDF_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_HKDF_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong hkdfId) {
    static const char *functionName = "NativeInterface.HKDF_delete";

    ICC_CTX *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    OCKHKDF *ockHKDF = (OCKHKDF *)((intptr_t)hkdfId);

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockHKDF == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
#ifdef DEBUG_HKDF_DETAIL
    if (debug) {
        gslogMessage("DETAIL_HKDF hkdfId : %lx ", (long)hkdfId);
        if (ockHKDF != NULL) {
            gslogMessage("DETAIL_HKDF ockHKDF->pctx : %lx ", ockHKDF->pctx);
        }
    }
#endif
    /* ICC_EVP_CTX_free(ockCtx, ockHKDF->pctx);*/
    if (ockHKDF->pctx != NULL) {
        ICC_CRYPTO_free(ockCtx, ockHKDF->pctx);
        ockHKDF->pctx = NULL;
    }
    FREE_N_NULL(ockHKDF);

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
