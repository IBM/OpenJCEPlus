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
#include <string.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_base_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSANONE_SIGNATURE_sign
 * Signature: (J[BJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSANONE_1SIGNATURE_1sign(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray digest,
    jlong dsaKeyId) {
    static const char *functionName = "NativeInterface.DSANONE_SIGNATURE_sign";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA            = (ICC_DSA *)((intptr_t)dsaKeyId);
    unsigned char *digestBytesNative = NULL;
    unsigned char *sigBytesLocal     = NULL;
    jbyteArray     sigBytes          = NULL;
    unsigned char *sigBytesNative    = NULL;
    jboolean       isCopy            = 0;
    int            sigLen            = 0;
    unsigned int   outLen            = 0;
    int            rc                = ICC_OSSL_SUCCESS;
    jbyteArray     retSigBytes       = NULL;
    int            NID               = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
        gslogMessage("DETAIL_SIGNATURE_DSANONE dsaKeyId %lx ", dsaKeyId);
#endif
    }
    if ((ockDSA == NULL) || (digest == NULL)) {
        throwOCKException(env, 0,
                          "Signature sign failed.The specified input "
                          "parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retSigBytes;
    }

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, digest, &isCopy));
    if (digestBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE_DSANONE FAILURE digestBytesNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        jint digestLength = (*env)->GetArrayLength(env, digest);

        sigLen = ICC_DSA_size(ockCtx, ockDSA);
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
        gslogMessage("DETAIL_SIGNATURE_DSANONE sigLen %d digestLength %d",
                     (int)sigLen, (int)digestLength);
#endif
        if (sigLen <= 0) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE_DSANONE FAILURE ICC_DSA_size ");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_DSA_size failed");
        } else {
            sigBytesLocal = (unsigned char *)malloc(sigLen);
            if (sigBytesLocal == NULL) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_SIGNATURE_DSANONE FAILURE sigBytesLocal ");
                }
#endif
                throwOCKException(env, 0, "malloc failed");
            } else {
                rc = ICC_DSA_sign(ockCtx, NID, digestBytesNative, digestLength,
                                  sigBytesLocal, &outLen, ockDSA);
                if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_SIGNATURE_DSANONE FAILURE ICC_DSA_Sign ");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_DSA_Sign failed");
                } else {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
                    gslogMessagePrefix(
                        "DETAIL_SIGNATURE_DSANONE Digest - %d bytes\n",
                        digestLength);
                    gslogMessageHex((char *)digestBytesNative, 0, digestLength,
                                    0, 0, NULL);

                    gslogMessagePrefix(
                        "DETAIL_SIGNATURE_DSANONE Signature - %d bytes\n",
                        outLen);
                    gslogMessageHex((char *)sigBytesLocal, 0, outLen, 0, 0,
                                    NULL);
#endif
                    sigBytes = (*env)->NewByteArray(env, outLen);
                    if (sigBytes == NULL) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_SIGNATURE_DSANONE FAILURE sigBytes");
                        }
#endif
                        throwOCKException(env, 0, "NewByteArray failed");
                    } else {
                        sigBytesNative =
                            (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                                env, sigBytes, &isCopy));
                        if (sigBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
                            if (debug) {
                                gslogMessage(
                                    "DETAIL_SIGNATURE_DSANONE FAILURE "
                                    "sigBytesNative");
                            }
#endif
                            throwOCKException(
                                env, 0, "NULL from GetPrimitiveArrayCritical");
                        } else {
                            memcpy(sigBytesNative, sigBytesLocal, outLen);
                            retSigBytes = sigBytes;
                        }
                    }
                }
            }
        }
    }

    if (digestBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, digest, digestBytesNative,
                                              0);
    }

    if (sigBytesLocal != NULL) {
        free(sigBytesLocal);
        sigBytesLocal = NULL;
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
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSANONE_SIGNATURE_verify
 * Signature: (J[BJ[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSANONE_1SIGNATURE_1verify(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray digest,
    jlong dsaKeyId, jbyteArray sigBytes) {
    static const char *functionName =
        "NativeInterface.DSANONE_SIGNATURE_verify";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA            = (ICC_DSA *)((intptr_t)dsaKeyId);
    unsigned char *digestBytesNative = NULL;
    unsigned char *sigBytesNative    = NULL;
    jboolean       isCopy            = 0;

    int      rc       = ICC_OSSL_SUCCESS;
    jboolean verified = 0;
    int      NID      = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
        gslogMessage("DETAIL_SIGNATURE_DSANONE dsaKeyId %lx ", dsaKeyId);
#endif
    }
    if ((ockDSA == NULL) || (digest == NULL) || (sigBytes == NULL)) {
        throwOCKException(env, 0,
                          "Signature verify failed. The specified input "
                          "parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return verified;
    }

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, digest, &isCopy));
    if (digestBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE_DSANONE FAILURE digestBytesNative");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        jint digestLength = (*env)->GetArrayLength(env, digest);
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE_DSANONE digestLength%d",
                         (int)digestLength);
        }
#endif

        sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, sigBytes, &isCopy));
        if (sigBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE_DSANONE FAILURE sigBytesNative");
            }
#endif
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        } else {
            jint size = (*env)->GetArrayLength(env, sigBytes);
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
            if (debug) {
                gslogMessagePrefix(
                    "DETAIL_SIGNATURE_DSANONE Signature to verify %d bytes:\n",
                    (int)size);
                gslogMessageHex((char *)sigBytesNative, 0, size, 0, 0, NULL);
            }
#endif
            rc = ICC_DSA_verify(ockCtx, NID, digestBytesNative, digestLength,
                                sigBytesNative, (unsigned int)size, ockDSA);
            if (ICC_OSSL_SUCCESS == rc) {
                verified = 1;
            } else {
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_SIGNATURE_DSANONE FAILURE ICC_DSA_verify ");
                }
#endif
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_DSA_Verify failed");
            }
        }
    }

    if (digestBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, digest, digestBytesNative,
                                              0);
    }

    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
#ifdef DEBUG_SIGNATURE_DSANONE_DETAIL
        gslogMessage(
            "DETAIL_SIGNATURE_DSANONE Signature verification result %d",
            (int)verified);
#endif
    }

    return verified;
}
