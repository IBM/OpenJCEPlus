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
#include <string.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>
#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    PQC_SIGNATURE_sign
 * Signature: (JJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_PQC_1SIGNATURE_1sign(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray data) {

    ICC_CTX          *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY     *ockPKey        = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    ICC_EVP_PKEY_CTX *skc            = NULL;
    unsigned char    *sigBytesLocal  = NULL;
    jbyteArray        sigBytes       = NULL;
    unsigned char    *sigBytesNative = NULL;
    unsigned char    *dataNative     = NULL;
    jboolean          isCopy         = 0;
    size_t            sigLen         = 0;
    size_t            datalen        = 0;
    int               rc             = ICC_OSSL_SUCCESS;
    jbyteArray        retSigBytes    = NULL;

    if ((ockPKey == NULL) || (data == NULL)) {
        throwOCKException(env, 0,
                          "Signature sign failed. The specified Signature "
                          "input parameters are incorrect.");
        return retSigBytes;
    }

    skc = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);
    if (!skc) {
        if (debug) {
            gslogMessage("ICC_EVP_PKEY_CTX_new  failed");
        }
        return retSigBytes;
    }

    rc = ICC_EVP_PKEY_sign_init(ockCtx, skc);
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_sign_init failed");
        return retSigBytes;
    }

    /* Get the length of the signature to allocate */
    datalen = (*env)->GetArrayLength(env, data);

    if (datalen == 0) {
        throwOCKException(
            env, 0, "Signature sign failed. Length of data to sign is 0.");
        return retSigBytes;
    }

    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data,
                                                                     &isCopy));
    if (NULL == dataNative) {
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
        return retSigBytes;
    }

    rc = ICC_EVP_PKEY_sign(ockCtx, skc, NULL, &sigLen, dataNative, datalen);
    if (ICC_OSSL_SUCCESS != rc) {
        ockCheckStatus(ockCtx);
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
        throwOCKException(env, 0, "ICC_EVP_PKEY_sign_init failed");
        return retSigBytes;
    }

    if (sigLen <= 0) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "Getting signature size failed");
    } else {
        sigBytesLocal = (unsigned char *)malloc(sigLen);
        if (sigBytesLocal == NULL) {
            throwOCKException(env, 0, "malloc failed");
        } else {
            rc = ICC_EVP_PKEY_sign(ockCtx, skc, sigBytesLocal, &sigLen,
                                   dataNative, datalen);
            if (ICC_OSSL_SUCCESS != rc) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_EVP_SignFinal failed");
            } else {
                sigBytes = (*env)->NewByteArray(env, sigLen);
                if (sigBytes == NULL) {
                    throwOCKException(env, 0, "NewByteArray failed");
                } else {
                    sigBytesNative =
                        (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                            env, sigBytes, &isCopy));
                    if (sigBytesNative == NULL) {
                        throwOCKException(
                            env, 0, "NULL from GetPrimitiveArrayCritical");
                    } else {
                        memcpy(sigBytesNative, sigBytesLocal, sigLen);
                        retSigBytes = sigBytes;
                    }
                }
            }
        }
    }

    if (skc != NULL) {
        ICC_EVP_PKEY_CTX_free(ockCtx, skc);
        skc = NULL;
    }
    if (sigBytesLocal != NULL) {
        free(sigBytesLocal);
        sigBytesLocal = NULL;
    }
    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    }
    if (dataNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
    }
    if ((sigBytes != NULL) && (retSigBytes == NULL)) {
        (*env)->DeleteLocalRef(env, sigBytes);
    }

    return retSigBytes;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    PQC_SIGNATURE_verify
 * Signature: (JJ[B[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_PQC_1SIGNATURE_1verify(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockPKeyId,
    jbyteArray sigBytes, jbyteArray data) {

    ICC_CTX          *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY     *ockPKey        = (ICC_EVP_PKEY *)((intptr_t)ockPKeyId);
    ICC_EVP_PKEY_CTX *evp_pk         = NULL;
    unsigned char    *sigBytesNative = NULL;
    unsigned char    *dataNative     = NULL;
    jboolean          isCopy         = 0;
    int               rc             = ICC_OSSL_SUCCESS;
    size_t            sigsize        = 0;
    size_t            datalen        = 0;
    jboolean          verified       = 0;

    if ((ockPKey == NULL) || (sigBytes == NULL)) {
        throwOCKException(
            env, 0,
            "Verify failed. The specified input parameters are incorrect.");
        return verified;
    }

    sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, sigBytes, &isCopy));
    if (sigBytesNative == NULL) {
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
        sigsize = (*env)->GetArrayLength(env, sigBytes);

        dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, data, &isCopy));

        if (dataNative == NULL) {
            (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
            throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
            return verified;
        }
        datalen = (*env)->GetArrayLength(env, data);

        /* EVP context */
        evp_pk = ICC_EVP_PKEY_CTX_new(ockCtx, ockPKey, NULL);

        if (!evp_pk) {
            throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new failed");
        } else {
            rc = ICC_EVP_PKEY_verify_init(ockCtx, evp_pk);

            if (rc != ICC_OSSL_SUCCESS) {
                throwOCKException(env, 0, "ICC_EVP_PKEY_verify_init failed");
            } else {
                rc = ICC_EVP_PKEY_verify(ockCtx, evp_pk, sigBytesNative,
                                         sigsize, dataNative, datalen);
                if (ICC_OSSL_SUCCESS == rc) {
                    verified = 1;
                } else {
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_EVP_PKEY_verify failed");
                }
            }
        }
    }

    if (evp_pk != NULL) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_pk);
    }

    if (dataNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
    }
    if (sigBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative,
                                              JNI_ABORT);
    }

    if (ICC_OSSL_SUCCESS == rc) {
        verified = 1;
    } else {
        if (debug) {
            gslogMessage("SIGNATURE_PQC  rc verify =%d: ", (long)rc);
        }
        throwOCKException(env, rc, "ICC_EVP_VerifyFinal failed");
    }

    return verified;
}
