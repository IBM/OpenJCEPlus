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
#include <string.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    SIGNATUREEdDSA_signOneShot
 * DigestSignature: (JJJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_SIGNATUREEdDSA_1signOneShot(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray bytes) {
    static const char *functionName   = "SIGNATUREEdDSA_signOneShot";
    ICC_CTX           *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY      *pkey           = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    ICC_EVP_PKEY_CTX  *pctx           = NULL;
    ICC_EVP_MD_CTX    *md_ctx         = NULL;
    unsigned char     *bytesNative    = NULL;
    unsigned char     *sigBytesLocal  = NULL;
    jbyteArray         sigBytes       = NULL;
    unsigned char     *sigBytesNative = NULL;
    jboolean           isCopy         = 0;
    int                rc             = ICC_OSSL_SUCCESS;
    jbyteArray         retSigBytes    = NULL;
    size_t             outLen         = 0;
    jint               size           = 0;
    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((pkey == NULL) || (bytes == NULL)) {
        throwOCKException(
            env, 0,
            "EdDSA signature failed. The input arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retSigBytes;
    }
    md_ctx = ICC_EVP_MD_CTX_new(ockCtx);
#ifdef iDEBUG_SIGNATURE_EDDSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE_EDDSA mdctx=%lx: ", (long)md_ctx);
    }
#endif
    if (NULL == md_ctx) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_MD_CTX_new failed");
    } else {
        bytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, bytes, &isCopy));
        if (bytesNative == NULL) {
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        } else {
            size = (*env)->GetArrayLength(env, bytes);
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE_EDDSA sigLen - %d", (int)size);
            }
#endif
            rc = ICC_EVP_DigestSignInit(ockCtx, md_ctx, &(pctx), NULL, NULL,
                                        pkey);
            if (ICC_OSSL_SUCCESS != rc) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
                gslogMessage(
                    "DETAIL_SIGNATURE_EDDSA Error: rc from "
                    "ICC_EVP_DigestSignInit rc=%d ",
                    rc);
#endif
                throwOCKException(env, 0, "ICC_EVP_DigestSignInit failed");
                if (debug) {
                    gslogFunctionExit(functionName);
                }
                return 0;
            } else {
                rc = ICC_EVP_DigestSign(ockCtx, md_ctx, NULL, &outLen,
                                        (unsigned char *)bytesNative, size);
                sigBytesLocal = malloc(outLen);
                if (sigBytesLocal == NULL) {
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
                    gslogMessage(
                        "DETAIL_SIGNATURE_EDDSA Error: sigBytesLocal malloc");
#endif
                    throwOCKException(env, 0, "malloc failed");
                } else {
                    rc = ICC_EVP_DigestSign(
                        ockCtx, md_ctx, (unsigned char *)sigBytesLocal, &outLen,
                        (unsigned char *)bytesNative, (unsigned int)size);
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
                    gslogMessage(
                        "DETAIL_SIGNATURE_EDDSA sigBytesLocal %lx outLen %d",
                        sigBytesLocal, outLen);
#endif
                    if (ICC_OSSL_SUCCESS != rc) {
                        ockCheckStatus(ockCtx);
                        throwOCKException(env, 0, "ICC_EVP_DigestSignFinal");
                    } else {
                        sigBytes = (*env)->NewByteArray(env, outLen);
                        if (sigBytes == NULL) {
                            throwOCKException(env, 0, "NewByteArray failed");
                        } else {
                            sigBytesNative =
                                (unsigned char
                                     *)((*env)->GetPrimitiveArrayCritical(
                                    env, sigBytes, &isCopy));
                            if (sigBytesNative == NULL) {
                                throwOCKException(
                                    env, 0,
                                    "NULL from GetPrimitiveArrayCritical");
                            } else {
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
                                gslogMessage(
                                    "DETAIL_SIGNATURE_EDDSA Calling memcpy "
                                    "sigbByesNative %lx sigBytesLocal %lx, "
                                    "outLen %d",
                                    sigBytesNative, sigBytesLocal, outLen);
#endif
                                memcpy((void *)sigBytesNative,
                                       (void *)sigBytesLocal, (size_t)outLen);
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
                                gslogMessage(
                                    "DETAIL_SIGNATURE_EDDSA memcpy successful");
#endif
                                retSigBytes = sigBytes;
                            }
                        }
                    }
                }
            }
        }
        if (md_ctx != NULL) {
            ICC_EVP_MD_CTX_free(ockCtx, md_ctx);
            md_ctx = NULL;
        }
    }

    FREE_N_NULL(sigBytesLocal);

    if (bytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, bytes, bytesNative, 0);
    }

    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    }

    if ((sigBytes != NULL) && (retSigBytes == NULL)) {
        (*env)->DeleteLocalRef(env, sigBytes);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
    return retSigBytes;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    SIGNATUREEdDSA_verifyOneShot
 * Signature: (JJ[B[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_SIGNATUREEdDSA_1verifyOneShot(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray sigBytes, jbyteArray oneShotBytes) {
    static const char *functionName   = "SIGNATUREEdDSA_verifyOneShot";
    ICC_CTX           *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY      *pkey           = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    ICC_EVP_PKEY_CTX  *pctx           = NULL;
    ICC_EVP_MD_CTX    *md_ctx         = NULL;
    unsigned char     *sigBytesNative = NULL;
    unsigned char     *sigBytesNativeRes = NULL;
    jboolean           isCopy            = 0;
    int                rc                = ICC_OSSL_SUCCESS;
    jboolean           verified          = 0;
    jint               size              = 0;
    jint               sizeRes           = 0;
    if ((pkey == NULL) || (sigBytes == NULL)) {
        throwOCKException(env, 0,
                          "EdDSA signature one shot verify failed. The input "
                          "arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return verified;
    }
    md_ctx = ICC_EVP_MD_CTX_new(ockCtx);
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE_EDDSA mdctx=%lx: ", (long)md_ctx);
    }
#endif
    if (NULL == md_ctx) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_MD_CTX_new failed");
    } else {
        sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, sigBytes, &isCopy));
        if (sigBytesNative == NULL) {
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        } else {
            sigBytesNativeRes =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, oneShotBytes, &isCopy));
            if (sigBytesNativeRes == NULL) {
                throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
            } else {
                size    = (*env)->GetArrayLength(env, sigBytes);
                sizeRes = (*env)->GetArrayLength(env, oneShotBytes);
#ifdef DEBUG_SIGNATURE_EDDSA_DATA
                if (debug) {
                    gslogMessage("DATA_SIGNATURE_EDDSA size - %d sizeRes - %d",
                                 (int)size, (int)sizeRes);
                }
#endif
                rc = ICC_EVP_DigestVerifyInit(ockCtx, md_ctx, &(pctx), NULL,
                                              NULL, pkey);
                if (ICC_OSSL_SUCCESS != rc) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
                    gslogMessage(
                        "DETAIL_SIGNATURE_EDDSA Error: rc from "
                        "ICC_EVP_DigestVerifyInit rc=%d ",
                        rc);
#endif
                    throwOCKException(env, 0,
                                      "ICC_EVP_DigestVerifyInit failed");
                    if (debug) {
                        gslogFunctionExit(functionName);
                    }
                    return 0;
                } else {
                    rc = ICC_EVP_DigestVerify(
                        ockCtx, md_ctx, (unsigned char *)sigBytesNative,
                        (unsigned int)size, (unsigned char *)sigBytesNativeRes,
                        (unsigned int)sizeRes);
                    if (ICC_OSSL_SUCCESS == rc) {
                        verified = 1;
                    } else {
#ifdef DEBUG_SIGNATURE_EDDSA_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_SIGNATURE_EDDSA FAILURE "
                                "ICC_EVP_Verify");
                        }
#endif
                        ockCheckStatus(ockCtx);
                        throwOCKException(env, 0, "ICC_EVP_VerifyFinal failed");
                    }
                }
            }
        }
        if (md_ctx != NULL) {
            ICC_EVP_MD_CTX_free(ockCtx, md_ctx);
            md_ctx = NULL;
        }
    }

    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    }

    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, oneShotBytes,
                                              sigBytesNativeRes, 0);
    }

    return verified;
}
