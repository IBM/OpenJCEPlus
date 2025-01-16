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
#include "Digest.h"
#include <stdint.h>

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    SIGNATURE_sign
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_SIGNATURE_1sign(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong iccMDId,
    jlong ockPKeyId, jboolean convert) {
    static const char *functionName = "NativeInterface.SIGNATURE_sign";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest     *ockDigest      = (OCKDigest *)((intptr_t)iccMDId);
    ICC_EVP_PKEY  *ockPKey        = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    unsigned char *sigBytesLocal  = NULL;
    jbyteArray     sigBytes       = NULL;
    unsigned char *sigBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            sigLen         = 0;
    unsigned int   outLen         = 0;
    int            rc             = ICC_OSSL_SUCCESS;
    jbyteArray     retSigBytes    = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockDigest == NULL) || (ockPKey == NULL)) {
        throwOCKException(env, 0,
                          "Signature sign failed. The specified Signature "
                          "input parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retSigBytes;
    } else if (ockDigest->mdCtx == NULL) {
        throwOCKException(env, 0,
                          "Signature sign failed. The specified Signature "
                          "input parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retSigBytes;
    }

#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE ockPKeyId %lx, iccMDId %lx", ockPKeyId,
                     iccMDId);
    }
#endif

    sigLen = ICC_EVP_PKEY_size(ockCtx, ockPKey);
#ifdef DEBUG_SIGNATURE_DETAIL
    if (debug) {
        gslogMessage("DETAIL_SIGNATURE sigLen %d", (int)sigLen);
    }
#endif
    if (sigLen <= 0) {
#ifdef DEBUG_SIGNATURE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE FAILURE ICC_EVP_PKEY_size");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_size failed");
    } else {
        sigBytesLocal = (unsigned char *)malloc(sigLen);
        if (sigBytesLocal == NULL) {
#ifdef DEBUG_SIGNATURE_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE FAILURE sigBytesLocal ");
            }
#endif
            throwOCKException(env, 0, "malloc failed");
        } else {
#ifdef DEBUG_SIGNATURE_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE sigBytes allocated");
            }
#endif

            // Only convert key if it is a plain RSA
            if (convert) {
                ICC_RSA *rsaKeyPtr = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
                ICC_RSA_FixEncodingZeros(ockCtx, rsaKeyPtr, NULL, 0);
            }

            rc = ICC_EVP_SignFinal(ockCtx, ockDigest->mdCtx, sigBytesLocal,
                                   &outLen, ockPKey);
            if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_SIGNATURE_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_SIGNATURE FAILURE ICC_EVP_SignFinal rc %d", rc);
                }
#endif
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_EVP_SignFinal failed");
            } else {
#ifdef DEBUG_SIGNATURE_DETAIL
                gslogMessagePrefix("DETAIL_SIGNATURE - %d bytes\n", outLen);
                gslogMessageHex((char *)sigBytesLocal, 0, outLen, 0, 0, NULL);
#endif
                sigBytes = (*env)->NewByteArray(env, outLen);
                if (sigBytes == NULL) {
#ifdef DEBUG_SIGNATURE_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_SIGNATURE FAILURE sigBytes ");
                    }
#endif
                    throwOCKException(env, 0, "NewByteArray failed");
                } else {
                    sigBytesNative =
                        (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                            env, sigBytes, &isCopy));
                    if (sigBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_SIGNATURE FAILURE sigBytesNative ");
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
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    SIGNATURE_verify
 * Signature: (JJJ)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_SIGNATURE_1verify(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong iccMDId,
    jlong ockPKeyId, jbyteArray sigBytes) {
    static const char *functionName = "NativeInterface.SIGNATURE_verify";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest     *ockDigest      = (OCKDigest *)((intptr_t)iccMDId);
    ICC_EVP_PKEY  *ockPKey        = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    unsigned char *sigBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            rc             = ICC_OSSL_SUCCESS;
    jboolean       verified       = 0;
    unsigned long  errCode;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockDigest == NULL) || (ockPKey == NULL) ||
        (ockDigest->mdCtx == NULL) || (sigBytes == NULL)) {
        throwOCKException(env, 0,
                          "Digest verify failed. The specified input "
                          "parameters are incorrect.");
        return verified;
    }

    sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, sigBytes, &isCopy));
    if (sigBytesNative == NULL) {
#ifdef DEBUG_SIGNATURE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE FAILURE sigBytesNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        jint size = (*env)->GetArrayLength(env, sigBytes);
#ifdef DEBUG_SIGNATURE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE ockPKeyId=%lx", (long)ockPKeyId);
            gslogMessagePrefix("DETAIL_SIGNATURE to verify %d bytes:\n",
                               (int)size);
            gslogMessageHex((char *)sigBytesNative, 0, (int)size, 0, 0, NULL);
            if (ockDigest != NULL) {
                gslogMessage("DETAIL_SIGNATURE ockDigest->mdCtx %lx",
                             ockDigest->mdCtx);
            }
        }
#endif
        rc = ICC_EVP_VerifyFinal(ockCtx, ockDigest->mdCtx, sigBytesNative,
                                 (unsigned int)size, ockPKey);
#ifdef DEBUG_SIGNATURE_DETAIL
        if (debug) {
            gslogMessage("DETAIL_SIGNATURE rc %d", (int)rc);
        }
#endif
        if (ICC_OSSL_SUCCESS == rc) {
            verified = 1;
        } else {
#ifdef DEBUG_SIGNATURE_DETAIL
            if (debug) {
                gslogMessage("DETAIL_SIGNATURE FAILURE ICC_EVP_VerifyFinal ");
            }
#endif
            errCode = ICC_ERR_peek_last_error(ockCtx);
            if (debug) {
                gslogMessage("errCode: %X", errCode);
            }
            if (errCode == 0x0D08303A) {
                throwOCKException(env, 0, "nested asn1 error");
            } else {
                throwOCKException(env, 0, "ICC_EVP_VerifyFinal failed");
            }
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_VerifyFinal failed");
        }
    }

    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return verified;
}
