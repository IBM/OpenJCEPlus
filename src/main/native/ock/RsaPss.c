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
#include "RsaPss.h"
#include <stdint.h>

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_signInit
 * DigestSignature: (JJJ)[B
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1signInit(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockRsaPssId,
    jlong ockPKeyId, jint saltlen, jboolean convert) {
    static const char *functionName = "NativeInterface.RSAPSS_signInit";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss *ockRsaPss = (OCKRsaPss *)((intptr_t)ockRsaPssId);
    int        rc        = ICC_OSSL_SUCCESS;
    int        rc1       = ICC_OSSL_SUCCESS;
    int        rc2       = ICC_OSSL_SUCCESS;
    int        saltl     = (int)saltlen;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockRsaPss == NULL) {
        throwOCKException(env, 0, "ockRsaPss cannot be null");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    } else {
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS ockRsaPssId=%lx ockPKeyId=%lx ",
                     (long)ockRsaPssId, (long)ockPKeyId);
#endif

        ockRsaPss->ockPKey    = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
        ockRsaPss->evpPkeyCtx = NULL;
    }

    // Only convert key if it is a plain RSA
    if (convert) {
        ICC_RSA *rsaKeyPtr = ICC_EVP_PKEY_get1_RSA(ockCtx, ockRsaPss->ockPKey);
        ICC_RSA_FixEncodingZeros(ockCtx, rsaKeyPtr, NULL, 0);
    }
    rc = ICC_EVP_MD_CTX_cleanup(ockCtx, ockRsaPss->ockDigest->mdCtx);
    if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS FAILURE ICC_EVP_MD_CTX_cleanup failed");
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_MD_CTX_cleanup failed");
    }
    ICC_EVP_MD_CTX_init(ockCtx, ockRsaPss->ockDigest->mdCtx);

    rc = ICC_EVP_DigestSignInit(
        ockCtx, ockRsaPss->ockDigest->mdCtx, &(ockRsaPss->evpPkeyCtx),
        ockRsaPss->ockDigest->md, NULL, ockRsaPss->ockPKey);
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
        gslogMessage(
            "DETAIL_RSAPSS Error: rc from ICC_EVP_DigestSignInit rc=%d ", rc);

#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage(
            "DETAIL_RSAPSS Error: rc from ICC_EVP_DigestSignInit rc=%d ", rc);
#endif
        throwOCKException(env, 0, "ICC_EVP_DigestSignInit failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    } else {
        rc = ICC_EVP_PKEY_CTX_ctrl(
            ockCtx, ockRsaPss->evpPkeyCtx, ICC_EVP_PKEY_RSA, -1,
            ICC_EVP_PKEY_CTRL_RSA_PADDING, ICC_RSA_PKCS1_PSS_PADDING, NULL);
        rc1 = ICC_EVP_PKEY_CTX_ctrl(
            ockCtx, ockRsaPss->evpPkeyCtx, ICC_EVP_PKEY_RSA,
            (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY),
            ICC_EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltl, NULL);
        rc2 = ICC_EVP_PKEY_CTX_ctrl(
            ockCtx, ockRsaPss->evpPkeyCtx, ICC_EVP_PKEY_RSA,
            (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY),
            ICC_EVP_PKEY_CTRL_RSA_MGF1_MD,
            (jlong)((intptr_t)(ockRsaPss->ockMGF1Digest)), NULL);

        if (ICC_OSSL_SUCCESS != rc || ICC_OSSL_SUCCESS != rc1 ||
            ICC_OSSL_SUCCESS != rc2) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_RSAPSS_DETAIL
            gslogMessage(
                "DETAIL_RSAPSS Error: ICC_EVP_PKEY_CTX_ctrl rc=%d rc1=%d, "
                "rc2=%d ",
                rc, rc1, rc2);
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_CTRL failed");
            if (debug) {
                gslogFunctionExit(functionName);
            }
            return -1;
        } else {
            if (debug) {
                gslogFunctionExit(functionName);
            }

            return 0;
        }
    }
}

/**/

/* ICC_EVP_SignUpdate(ctx,md_ctx,Msg_buf,Msg_len);
sig_len = modulus/4;
rv = ICC_EVP_DigestSignFinal(ctx,md_ctx,sig_buf,&sig_len);*/

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_verifyInit
 * DigestSignature: (JJJ)[B
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1verifyInit(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockRsaPssId,
    jlong ockPKeyId, jint saltlen) {
    static const char *functionName = "NativeInterface.RSAPSS_verifyInit";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss *ockRsaPss = (OCKRsaPss *)((intptr_t)ockRsaPssId);
    int        rc        = ICC_OSSL_SUCCESS;
    int        rc1       = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockRsaPss == NULL) {
        throwOCKException(env, 0, "ockRsaPss cannot be null");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    } else {
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS ockRsaPssId=%lx ockPKeyId=%lx ",
                     (long)ockRsaPssId, (long)ockPKeyId);
        ;
#endif
        ockRsaPss->ockPKey    = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
        ockRsaPss->evpPkeyCtx = NULL;
    }

    rc = ICC_EVP_MD_CTX_cleanup(ockCtx, ockRsaPss->ockDigest->mdCtx);
    if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS FAILURE ICC_EVP_MD_CTX_cleanup failed");
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_MD_CTX_cleanup failed");
    }
    ICC_EVP_MD_CTX_init(ockCtx, ockRsaPss->ockDigest->mdCtx);

    rc = ICC_EVP_DigestVerifyInit(
        ockCtx, ockRsaPss->ockDigest->mdCtx, &(ockRsaPss->evpPkeyCtx),
        ockRsaPss->ockDigest->md, NULL, ockRsaPss->ockPKey);
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage(
            "DETAIL_RSAPSS Error: rc from ICC_EVP_DigestVerifyInit rc=%d ", rc);
#endif
        throwOCKException(env, 0, "ICC_EVP_DigestVerifyInit failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return -1;
    } else {
        rc = ICC_EVP_PKEY_CTX_ctrl(
            ockCtx, ockRsaPss->evpPkeyCtx, ICC_EVP_PKEY_RSA, -1,
            ICC_EVP_PKEY_CTRL_RSA_PADDING, ICC_RSA_PKCS1_PSS_PADDING, NULL);
        rc1 = ICC_EVP_PKEY_CTX_ctrl(
            ockCtx, ockRsaPss->evpPkeyCtx, ICC_EVP_PKEY_RSA,
            (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY),
            ICC_EVP_PKEY_CTRL_RSA_MGF1_MD,
            (jlong)((intptr_t)(ockRsaPss->ockMGF1Digest)), NULL);
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS ICC_EVP_PKEY_CTX_ctrl rc=%d rc1=%d ", rc,
                     rc1);
#endif
        if (ICC_OSSL_SUCCESS != rc || ICC_OSSL_SUCCESS != rc1) {
            return -1;
        }

        if (debug) {
            gslogFunctionExit(functionName);
        }

        return 0;
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_getSigLen
 * DigestSignature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1getSigLen(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockRsaPssId) {
    /*static const char * functionName = "NativeInterface.RSAPSS_getSigLen";*/

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss *ockRsaPss = (OCKRsaPss *)((intptr_t)ockRsaPssId);
    OCKDigest *ockDigest = NULL;

    size_t outLen = 0;
    if (ockRsaPss == NULL) {
        throwOCKException(env, 0, "RsaPss identifier is incorrect.");
        return outLen;
    }
    ockDigest = (OCKDigest *)ockRsaPss->ockDigest;
    if (ockDigest == NULL) {
        throwOCKException(env, 0, "RsaPss Digest identifier is incorrect.");
        return outLen;
    }
    ICC_EVP_DigestSignFinal(
        ockCtx, ockDigest->mdCtx, NULL,
        &outLen);  // Learn what the outlen value should actually be
    return outLen;
}
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_signFinal
 * DigestSignature: (JJJ[BI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1signFinal(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockRsaPssId,
    jbyteArray signature, jint length) {
    static const char *functionName = "NativeInterface.RSAPSS_signFinal";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss *ockRsaPss = (OCKRsaPss *)((intptr_t)ockRsaPssId);
    OCKDigest *ockDigest = NULL;

    ICC_EVP_PKEY *ockPKey = NULL;

    unsigned char *sigBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            sigLen         = 0;
    size_t         outLen         = length;
    int            rc             = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockRsaPss == NULL) || (signature == NULL) || (length < 0)) {
        throwOCKException(env, 0, "RsaPss Signature arguments are incorrect.");
        return;
    }

    ockDigest = (OCKDigest *)ockRsaPss->ockDigest;
    ockPKey   = (ICC_EVP_PKEY *)ockRsaPss->ockPKey;
    if ((ockDigest == NULL) || (ockPKey == NULL)) {
        throwOCKException(
            env, 0,
            "RsaPss Signature digest and private key arguments are incorrect.");
        return;
    }
    sigLen = ICC_EVP_PKEY_size(ockCtx, ockPKey);
#ifdef DEBUG_RSAPSS_DETAIL
    gslogMessage("DETAIL_RSAPSS sigLen=%d ", sigLen);
#endif

    if (sigLen <= 0) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_size failed");
    } else {
        sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, signature, &isCopy));

        if (sigBytesNative == NULL) {
            throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical");
        } else {
            rc = ICC_EVP_DigestSignFinal(ockCtx, ockDigest->mdCtx,
                                         sigBytesNative, &outLen);

#ifdef DEBUG_RSAPSS_DETAIL
            gslogMessage("DETAIL_RSAPSS sigBytesNative %lx outLen %d",
                         sigBytesNative, outLen);
#endif
            if (ICC_OSSL_SUCCESS != rc) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_EVP_DigestSignFinal");
            }
        }
    }
    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, signature, sigBytesNative,
                                              0);
    }

#ifdef DEBUG_RSAPSS_DETAIL
    gslogMessage("DETAIL_RSAPSS ockDigest->mdCtx=%lx ockDigest->md=%lx : ",
                 ockDigest->mdCtx, ockDigest->md);
#endif

    // Reset digest
    rc = ICC_EVP_DigestInit(ockCtx, ockDigest->mdCtx, ockDigest->md);
    if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS FAILURE ICC_EVP_DigestInit failed");
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_DigestInit failed");
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_verifyFinal
 * Signature: (JJJ)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1verifyFinal(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockRsaPssId,
    jbyteArray sigBytes, jint size) {
    static const char *functionName = "NativeInterface.RSAPSS_verifyFinal";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss     *ockRsaPss      = (OCKRsaPss *)((intptr_t)ockRsaPssId);
    OCKDigest     *ockDigest      = NULL;
    ICC_EVP_PKEY  *ockPKey        = NULL;
    unsigned char *sigBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            rc             = ICC_OSSL_SUCCESS;
    jboolean       verified       = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockRsaPss == NULL) || (sigBytes == NULL) || (size < 0)) {
        throwOCKException(
            env, 0, "RsaPss Signature verification arguments are incorrect.");
        return verified;
    }
    ockDigest = (OCKDigest *)ockRsaPss->ockDigest;
    ockPKey   = (ICC_EVP_PKEY *)ockRsaPss->ockPKey;

    if ((ockDigest == NULL) || (ockPKey == NULL)) {
        throwOCKException(env, 0,
                          "RsaPss Signature verification digest and private "
                          "key arguments are incorrect.");
        return verified;
    }
    sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, sigBytes, &isCopy));
    if (sigBytesNative == NULL) {
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
#ifdef DEBUG_RSAPSS_DATA
        gslogMessagePrefix("DETAIL_RSAPSS Signature to verify %d bytes:\n ",
                           (int)size);
        gslogMessageHex((char *)sigBytesNative, 0, size, 0, 0, NULL);
#endif
        rc = ICC_EVP_DigestVerifyFinal(ockCtx, ockDigest->mdCtx, sigBytesNative,
                                       (unsigned int)size);
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS ICC_EVP_DigestVerifyFinal rc=%d ", rc);
#endif
        if (ICC_OSSL_SUCCESS == rc) {
            verified = 1;
        } else {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_DigestVerifyFinal failed");
        }
    }

    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    }
    // Reset digest
    rc = ICC_EVP_DigestInit(ockCtx, ockDigest->mdCtx, ockDigest->md);
    if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_RSAPSS_DETAIL
        gslogMessage("DETAIL_RSAPSS FAILURE ICC_EVP_DigestInit failed");
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_DigestInit failed");
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

#ifdef DEBUG_RSAPSS_DETAIL
    gslogMessage("DETAIL_RSAPSS verifiedICC_EVP_DigestVerifyFinal verified=%d ",
                 verified);
#endif
    return verified;
}
//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_digestUpdate
 * Signature: (JJ[BII)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1digestUpdate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaPssId,
    jbyteArray data, jint offset, jint dataLen) {
    static const char *functionName = "NativeInterface.RSAPSS_digestUpdate";

    ICC_CTX       *ockCtx     = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss     *ockRsaPss  = (OCKRsaPss *)((intptr_t)rsaPssId);
    OCKDigest     *ockDigest  = NULL;
    unsigned char *dataNative = NULL;
    jboolean       isCopy     = 0;
    int            rc         = ICC_OSSL_SUCCESS;
    int            ockOffset  = (int)offset;
    int            ockDataLen = (int)dataLen;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockRsaPss == NULL) || (data == NULL) || (offset < 0) ||
        (offset > dataLen)) {
        throwOCKException(
            env, 0, "RsaPss Signature verification arguments are incorrect.");
        return;
    }
    ockDigest = ockRsaPss->ockDigest;
    if ((ockDigest == NULL) || (ockDigest->mdCtx == NULL)) {
        throwOCKException(
            env, 0, "RsaPss Signature verification arguments are incorrect.");
        return;
    }
#ifdef DEBUG_RSAPSS_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSAPSS digestId=%d :", (long)ockDigest);
    }
#endif
    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data,
                                                                     &isCopy));
    if (NULL == dataNative) {
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
#ifdef DEBUG_RSAPSS_DATA
        if (debug) {
            gslogMessagePrefix("DATA_RSAPSS %d bytes to update : ",
                               (int)ockDataLen);
            gslogMessageHex((char *)dataNative + offset, 0, (int)dataLen, 0, 0,
                            NULL);
        }
#endif

        rc = ICC_EVP_DigestUpdate(ockCtx, ockDigest->mdCtx,
                                  dataNative + ockOffset, (int)ockDataLen);
#ifdef DEBUG_RSAPSS_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSAPSS rc=%d: ", rc);
        }
#endif
        if (ICC_OSSL_SUCCESS != rc) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_DigestUpdate failed");
        }
    }

    if (dataNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Method:   allocateDigest
 */
OCKDigest *allocateDigest(JNIEnv *env, ICC_CTX *ockCtx, jstring digestAlgo) {
    OCKDigest  *ockDigest       = (OCKDigest *)malloc(sizeof(OCKDigest));
    const char *digestAlgoChars = NULL;

    if (ockDigest == NULL) {
        throwOCKException(env, 0, "Error allocating OCKDigest");
        return 0;
    } else {
        ockDigest->md    = NULL;
        ockDigest->mdCtx = NULL;
    }

    if (!(digestAlgoChars = (*env)->GetStringUTFChars(env, digestAlgo, NULL))) {
        throwOCKException(env, 0, "GetStringUTFChars() failed");
        FREE_N_NULL(ockDigest);
        return 0;
    }

    if (debug) {
        gslogMessage("DETAIL_RSAPSS digestAlgorithm=%s", digestAlgoChars);
    }

    ockDigest->md = ICC_EVP_get_digestbyname(ockCtx, digestAlgoChars);
#ifdef DEBUG_RSAPSS_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSAPSS ockDigest->md=%x: ", ockDigest->md);
    }
#endif
    if (NULL == ockDigest->md) {
        ockCheckStatus(ockCtx);
        (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);
        throwOCKException(env, 0, "ICC_EVP_get_digestbyname failed");
        FREE_N_NULL(ockDigest);
        return 0;
    } else {
        ockDigest->mdCtx = ICC_EVP_MD_CTX_new(ockCtx);
#ifdef DEBUG_RSAPSS_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSAPSS ockDigest->md=%ld: ",
                         (long)ockDigest->mdCtx);
        }
#endif
        if (NULL == ockDigest->mdCtx) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_MD_CTX_new failed");
        } else {
            ICC_EVP_MD_CTX_init(ockCtx, ockDigest->mdCtx);
        }
    }

    (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);

    return ockDigest;
}
//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_createContext
 * Signature: (JLjava/lang/String;)J
 */

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1createContext(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring digestAlgo,
    jstring mgf1SpecAlgo) {
    static const char *functionName = "NativeInterface.RSAPSS_createContext";
    ICC_CTX           *ockCtx       = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss         *ockRsaPss    = (OCKRsaPss *)malloc(sizeof(OCKRsaPss));

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRsaPss == NULL) {
        throwOCKException(env, 0, "Error allocating OCKRsaPss");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jlong)0;
    }

    ockRsaPss->ockPKey    = NULL;
    ockRsaPss->evpPkeyCtx = NULL;

    ockRsaPss->ockDigest = allocateDigest(env, ockCtx, digestAlgo);

    if (ockRsaPss->ockDigest != NULL) {
        // Only do this if the above did not fail.
        ockRsaPss->ockMGF1Digest = allocateDigest(env, ockCtx, mgf1SpecAlgo);
    } else {
        ockRsaPss->ockMGF1Digest = NULL;
    }

    return (jlong)((intptr_t)ockRsaPss);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_releaseContext
 * Signature: (JJ)V
 */

JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1releaseContext(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockRsaPssId) {
    static const char *functionName = "NativeInterface.RSAPSS_releaseContext";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss *ockRsaPss = (OCKRsaPss *)((intptr_t)ockRsaPssId);

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockRsaPss == NULL) {
        throwOCKException(env, 0, "Error allocating OCKRsaPss");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
    if (ockRsaPss->ockDigest != NULL) {
        if ((ockRsaPss->ockDigest->mdCtx) != NULL) {
            ICC_EVP_MD_CTX_cleanup(ockCtx, ockRsaPss->ockDigest->mdCtx);
            ICC_EVP_MD_CTX_free(ockCtx, ockRsaPss->ockDigest->mdCtx);
            ockRsaPss->ockDigest->mdCtx = NULL;
        }
    }
    if (ockRsaPss->ockMGF1Digest != NULL) {
        if ((ockRsaPss->ockMGF1Digest->mdCtx) != NULL) {
            ICC_EVP_MD_CTX_cleanup(ockCtx, ockRsaPss->ockMGF1Digest->mdCtx);
            ICC_EVP_MD_CTX_free(ockCtx, ockRsaPss->ockMGF1Digest->mdCtx);
            ockRsaPss->ockMGF1Digest->mdCtx = NULL;
        }
    }

    FREE_N_NULL(ockRsaPss->ockDigest);
    FREE_N_NULL(ockRsaPss->ockMGF1Digest);
    FREE_N_NULL(ockRsaPss);

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_reset
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1reset(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong digestId) {
    static const char *functionName = "NativeInterface.RSAPSS_reset";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKDigest *ockDigest = (OCKDigest *)((intptr_t)digestId);
    int        rc        = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockDigest == NULL) {
        throwOCKException(
            env, 0, "The specified RsaPss digest identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_RSAPSS ockDigest->mdCtx=%lx digestId %lx ockDigest->md=%lx "
            ": ",
            ockDigest->mdCtx, (long)digestId, ockDigest->md);
    }
#endif
    rc = ICC_EVP_MD_CTX_cleanup(ockCtx, ockDigest->mdCtx);
    if (ICC_OSSL_SUCCESS != rc) {
#ifdef DEBUG_DIGEST_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSAPSS FAILURE ICC_EVP_MD_CTX_cleanup failed");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_MD_CTX_cleanup failed");
    }

    ICC_EVP_MD_CTX_init(ockCtx, ockDigest->mdCtx);

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAPSS_resetDigest
 * Signature: (JJ)V
 */

JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAPSS_1resetDigest(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockRsaPssId) {
    static const char *functionName = "NativeInterface.RSAPSS_resetDigest";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKRsaPss *ockRsaPss = (OCKRsaPss *)((intptr_t)ockRsaPssId);
    int        rc        = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRsaPss == NULL) {
        throwOCKException(env, 0, "OCKRsaPss context is not valid");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

    if (ockRsaPss->ockDigest == NULL) {
        throwOCKException(env, 0, "OCKRsaPss digest context is not valid");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }

#ifdef DEBUG_DIGEST_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_DIGEST ockRsaPss->ockDigest->mdCtx=%x "
            "ockRsaPss->ockDigest->md=%x : ",
            ockRsaPss->ockDigest->mdCtx, ockRsaPss->ockDigest->md);
    }
#endif
    rc = ICC_EVP_DigestInit(ockCtx, ockRsaPss->ockDigest->mdCtx,
                            ockRsaPss->ockDigest->md);
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
