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

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

//------------------------------------------------------------------------------
// NOTE:
//
// This implementation uses the OCK methods ICC_RSA_sign and ICC_RSA_verify
// methods, which requires the digest to be exactly 36 bytes.
//
// This implementation differs from the RSAforSSL algorithm in OpenJCEPlus and
// OpenJCEPlusFIPS which processes at most 36 bytes for the digest.
//
// At the current time this implementation is not used by the OpenJCEPlus
// provider.
//------------------------------------------------------------------------------

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSASSL_SIGNATURE_sign
 * Signature: (J[BJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSASSL_1SIGNATURE_1sign(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray digest,
    jlong rsaKeyId) {
    static const char *functionName = "NativeInterface.RSASSL_SIGNATURE_sign";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA            = (ICC_RSA *)((intptr_t)rsaKeyId);
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
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
        gslogMessage("DETAIL_SIG_RSASSL rsaKeyId %lx", (long)rsaKeyId);
#endif
    }
    if ((digest == NULL) || (ockRSA == NULL)) {
        throwOCKException(env, 0,
                          "RSA SSL Signature input arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retSigBytes;
    }
#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
    NID = ICC_OBJ_txt2nid(ockCtx, "MD5-SHA1");
#ifdef __MVS__
#pragma convert(pop)
#endif
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIG_RSASSL NID %d", NID);
    }
#endif

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, digest, &isCopy));
    if (digestBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIG_RSASSL FAILURE digestBytesNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        jint digestLength = (*env)->GetArrayLength(env, digest);

        sigLen = ICC_RSA_size(ockCtx, ockRSA);
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIG_RSASSL sigLen - %d digestLen %d", sigLen,
                         (int)digestLength);
        }
#endif
        if (sigLen <= 0) {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIG_RSASSL FAILURE ICC_RSA_size ");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_RSA_size failed");
        } else {
            sigBytesLocal = (unsigned char *)malloc(sigLen);
            if (sigBytesLocal == NULL) {
                throwOCKException(env, 0, "malloc failed");
            } else {
                rc = ICC_RSA_sign(ockCtx, NID, digestBytesNative, digestLength,
                                  sigBytesLocal, &outLen, ockRSA);
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_SIG_RSASSL rc from ICC_RSA_Sign - %d outLen %d",
                        rc, outLen);
                }
#endif
                if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_SIG_RSASSL FAILURE ICC_RSA_sign %d ", rc);
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_RSA_Sign failed");
                } else {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
                    if (debug) {
                        gslogMessagePrefix(
                            "DETAIL_SIG_RSASSL Digest - %d bytes\n",
                            digestLength);
                        gslogMessageHex((char *)digestBytesNative, 0,
                                        digestLength, 0, 0, NULL);

                        gslogMessagePrefix(
                            "DETAIL_SIG_RSASSL Signature - %d bytes\n", outLen);
                        gslogMessageHex((char *)sigBytesLocal, 0, outLen, 0, 0,
                                        NULL);
                    }
#endif
                    sigBytes = (*env)->NewByteArray(env, outLen);
                    if (sigBytes == NULL) {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
                        if (debug) {
                            gslogMessage("DETAIL_SIG_RSASSL FAILURE sigBytes ");
                        }
#endif
                        throwOCKException(env, 0, "NewByteArray failed");
                    } else {
                        sigBytesNative =
                            (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                                env, sigBytes, &isCopy));
                        if (sigBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
                            if (debug) {
                                gslogMessage(
                                    "DETAIL_SIG_RSASSL FAILURE sigBytesNative");
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

    FREE_N_NULL(sigBytesLocal);

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
 * Method:    RSASSL_SIGNATURE_verify
 * Signature: (J[BJ[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSASSL_1SIGNATURE_1verify(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray digest,
    jlong rsaKeyId, jbyteArray sigBytes, jboolean convert) {
    static const char *functionName = "NativeInterface.RSASSL_SIGNATURE_verify";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA            = (ICC_RSA *)((intptr_t)rsaKeyId);
    unsigned char *digestBytesNative = NULL;
    unsigned char *sigBytesNative    = NULL;
    jboolean       isCopy            = 0;

    int      rc       = ICC_OSSL_SUCCESS;
    jboolean verified = 0;
    int      NID;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
        gslogMessage("DETAIL_SIG_RSASSL rsaKeyId %lx", (long)rsaKeyId);
#endif
    }
    if ((digest == NULL) || (ockRSA == NULL)) {
        throwOCKException(
            env, 0,
            "RSA SSL Signature verification input arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return verified;
    }
#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
    NID = ICC_OBJ_txt2nid(ockCtx, "MD5-SHA1");
#ifdef __MVS__
#pragma convert(pop)
#endif
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIG_RSASSL NID %d", NID);
    }
#endif

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, digest, &isCopy));
    if (digestBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIG_RSASSL FAILURE digestBytesNative");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        jint digestLength = (*env)->GetArrayLength(env, digest);
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIG_RSASSL digestLength=%d",
                         (int)digestLength);
        }
#endif

        sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, sigBytes, &isCopy));
        if (sigBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIG_RSASSL FAILURE sigBytesNative");
            }
#endif
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        } else {
            jint size = (*env)->GetArrayLength(env, sigBytes);
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
            if (debug) {
                gslogMessagePrefix(
                    "DETAIL_SIG_RSASSL Signature to verify %d bytes:\n",
                    (int)size);
                gslogMessageHex((char *)sigBytesNative, 0, size, 0, 0, NULL);
            }
#endif

            if (convert) {
                ICC_RSA_FixEncodingZeros(ockCtx, ockRSA, NULL, 0);
            }

            rc = ICC_RSA_verify(ockCtx, NID, digestBytesNative, digestLength,
                                sigBytesNative, (unsigned int)size, ockRSA);
            if (ICC_OSSL_SUCCESS == rc) {
                verified = 1;
            } else {
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_SIG_RSASSL FAILURE ICC_RSA_Verify ");
                }
#endif
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_RSA_Verify failed");
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
#ifdef DEBUG_SIGNATURE_RSASSL_DETAIL
        gslogMessage("DETAIL_SIG_RSASSL Signature verification Result %d ",
                     (int)verified);
#endif
        gslogFunctionExit(functionName);
    }

    return verified;
}
