/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_create
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1create(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jstring digestAlgo) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_create";

    EVP_MD      *md              = NULL;
    EVP_MD_CTX  *mdCtx           = NULL;
    const char  *digestAlgoChars = NULL;
    jlong       digestId         = 0;
    int         rc               = 1;

    if (NULL == digestAlgo) {
        throwOSSLException(env, 0, "DIGEST_create: The specified digest algorithm is null");
        return 0;
    }

    if (!(digestAlgoChars = (const char *)(*env)->GetStringUTFChars(env, digestAlgo, NULL))) {
        throwOSSLException(env, 0, "DIGEST_create: GetStringUTFChars() failed");
        goto cleanup;
    }

    md = EVP_MD_fetch(NULL, digestAlgoChars, NULL);
    if (NULL == md) {
        throwOSSLException(env, 0, "DIGEST_create: EVP_MD_fetch failed");
        goto cleanup;
    }

    mdCtx = EVP_MD_CTX_new();
    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_create: EVP_MD_CTX_new failed");
        goto cleanup;
    }

    rc = EVP_DigestInit_ex2(mdCtx, md, NULL);
    if (1 != rc) {
        throwOSSLException(env, 0, "DIGEST_create: EVP_DigestInit_ex2 failed");
        goto cleanup;
    }

    // Everything succeeded. Set digestId to created EVP_MD_CTX.
    digestId = (jlong)((intptr_t)mdCtx);

cleanup:
    /*
     * EVP_DigestInit_ex2 calls EVP_MD_up_ref and stores the EVP_MD as
     * ctx->fetched_digest inside mdCtx.  EVP_MD_CTX_free will release that
     * reference.  We must always release our own fetch reference here,
     * regardless of success or failure, to avoid a refcount leak.
     * On the error path mdCtx is freed below (which drops its reference),
     * then we drop ours.  If mdCtx was never initialised we just drop ours.
     */
    EVP_MD_free(md);
    md = NULL;

    (*env)->ReleaseStringUTFChars(env, digestAlgo, digestAlgoChars);
    if (0 == digestId) {
        if (NULL != mdCtx) {
            EVP_MD_CTX_free(mdCtx);
            mdCtx = NULL;
        }
    }

    return digestId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_copy
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1copy(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_copy";

    EVP_MD_CTX *mdCtx       = (EVP_MD_CTX *)((intptr_t)digestId);
    EVP_MD_CTX *mdCtxCopy   = NULL;
    jlong      digestCopyId = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_copy: The specified mdCtx is null");
        return 0;
    }

    mdCtxCopy = EVP_MD_CTX_new();
    if (NULL == mdCtxCopy) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_copy: EVP_MD_CTX_new failed");
        goto cleanup;
    }

    if (1 != EVP_MD_CTX_copy(mdCtxCopy, mdCtx)) {
        throwOSSLException(env, 0, "DIGEST_copy: EVP_MD_CTX_copy failed");
        goto cleanup;
    }

    // Everything succeeded. Set digestCopyId to copied EVP_MD_CTX.
    digestCopyId = (jlong)((intptr_t)mdCtxCopy);

cleanup:
    if (digestCopyId == 0) {
        if (NULL != mdCtxCopy) {
            EVP_MD_CTX_free(mdCtxCopy);
            mdCtxCopy = NULL;
        }
    }

    return digestCopyId;
}

static int DIGEST_update_internal(JNIEnv *env, EVP_MD_CTX *mdCtx, unsigned char *dataNative, int dataLen) {
    int rc = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_update_internal: The specified mdCtx is null");
        return 0;
    }

    if (dataLen < 0) {
        throwOSSLException(env, 0, "DIGEST_update_internal: The specified data length is negative");
        return 0;
    }

    rc = EVP_DigestUpdate(mdCtx, dataNative, dataLen);
    if (1 != rc) {
        throwOSSLException(env, 0, "DIGEST_update_internal: EVP_DigestUpdate failed");
    }

    return rc;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_update
 * Signature: (J[BII)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1update(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray data, jint offset, jint dataLen) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_update";

    EVP_MD_CTX     *mdCtx       = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char  *dataNative  = NULL;
    jboolean       isCopy       = 0;
    int            returnResult = 0;

    if (NULL == data) {
        throwOSSLException(env, 0, "DIGEST_update: The specified data array is null");
        return 0;
    }

    if (offset < 0) {
        throwOSSLException(env, 0, "DIGEST_update: The specified offset is negative");
        return 0;
    }

    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data, &isCopy));
    if (NULL == dataNative) {
        throwOSSLException(env, 0, "DIGEST_update: GetPrimitiveArrayCritical failed");
        return 0;
    }

    returnResult = DIGEST_update_internal(env, mdCtx, dataNative + offset, dataLen);

    (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, 0);

    return (jint)returnResult;
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_updateFastJNI
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1updateFastJNI(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jlong dataBuffer, jint dataLen) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_updateFastJNI";

    EVP_MD_CTX     *mdCtx       = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char   *dataNative = (unsigned char *)dataBuffer;

    if (dataNative == NULL) {
        throwOSSLException(env, 0, "DIGEST_updateFastJNI: The pointer to the specified data buffer is null");
        return;
    }

    DIGEST_update_internal(env, mdCtx, dataNative, (int)dataLen);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_digest";

    EVP_MD_CTX     *mdCtx            = (EVP_MD_CTX *)((intptr_t)digestId);
    jbyteArray     digestBytes       = NULL;
    unsigned char *digestBytesNative = NULL;
    jboolean       isCopy            = 0;
    int            digestLen         = 0;
    int            rc                = 0;
    jbyteArray     retDigestBytes    = NULL;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_digest: The specified mdCtx is null");
        return 0;
    }

    rc = EVP_DigestFinal_ex(mdCtx, NULL, (unsigned int *)&digestLen);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest: EVP_DigestFinal_ex failed");
        goto cleanup;
    }

    digestBytes = (*env)->NewByteArray(env, digestLen);
    if (NULL == digestBytes) {
        throwOSSLException(env, 0, "DIGEST_digest: NewByteArray failed");
        return 0;
    }

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, digestBytes, &isCopy));
    if (NULL == digestBytesNative) {
        throwOSSLException(env, 0, "DIGEST_digest: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    rc = EVP_DigestFinal_ex(mdCtx, digestBytesNative, (unsigned int *)&digestLen);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest: EVP_DigestFinal_ex failed");
        goto cleanup;
    }

    // Everything succeeded. Set retDigestBytes to the jbytearray with the result.
    retDigestBytes = digestBytes;

cleanup:
    if (digestBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, digestBytes, digestBytesNative, 0);
    }

    if ((digestBytes != NULL) && (retDigestBytes == NULL)) {
        (*env)->DeleteLocalRef(env, digestBytes);
    }

    return retDigestBytes;
}

static int
DIGEST_digest_and_reset_internal(JNIEnv *env, jlong osslContextId, EVP_MD_CTX *mdCtx, unsigned char *digestBytesNative, unsigned int digestLen)
{
    int rc = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: The specified mdCtx is null");
        return 0;
    }

    if (NULL == digestBytesNative) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: The pointer to the specified data array is null");
        return 0;
    }

    if (digestLen < 0) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: The specified data length is negative");
        return 0;
    }

    rc = EVP_DigestFinal_ex(mdCtx, digestBytesNative, &digestLen);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: EVP_DigestFinal_ex failed");
        return rc;
    }

    /* digest reset */
    rc = EVP_DigestInit_ex2(mdCtx, NULL, NULL);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_digest_and_reset_internal: EVP_DigestInit_ex2 failed");
    }

    return rc;
}
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest_and_reset
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest_1and_1reset__JJI(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jlong digestBytes, jint length) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_digest_and_reset";

    EVP_MD_CTX     *mdCtx             = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char  *digestBytesNative = (unsigned char *)((intptr_t)digestBytes);
    unsigned int   digestLen          = (unsigned int)length;

    DIGEST_digest_and_reset_internal(env, osslContextId, mdCtx, digestBytesNative, digestLen);
}

/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_digest_and_reset
 * Signature: (J[B)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1digest_1and_1reset__JJ_3B(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId,
    jbyteArray digestBytes) {
    ////static const char *functionName = "NativeOSSLImplementation.DIGEST_digest_and_reset";

    EVP_MD_CTX    *mdCtx             = (EVP_MD_CTX *)((intptr_t)digestId);
    unsigned char *digestBytesNative = NULL;
    jboolean      isCopy             = 0;
    int           returnResult       = 0;
    unsigned int  digestLen          = 0;

    if (NULL == digestBytes) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset: The specified data array is null");
        return 0;
    }

    digestBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, digestBytes, &isCopy));
    if (digestBytesNative == NULL) {
        throwOSSLException(env, 0, "DIGEST_digest_and_reset: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    returnResult = DIGEST_digest_and_reset_internal(env, osslContextId, mdCtx, digestBytesNative, digestLen);

cleanup:
    if (digestBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, digestBytes, digestBytesNative, 0);
    }

    return (jint)returnResult;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_size
 * Signature: (J)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1size(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {
    ////static const char *functionName = "NativeOSSLImplementation.DIGEST_size";

    EVP_MD_CTX *mdCtx    = (EVP_MD_CTX *)((intptr_t)digestId);
    int        digestLen = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_size: The specified mdCtx is null");
        return 0;
    }

    digestLen = EVP_MD_CTX_get_size(mdCtx);
    if (0 >= digestLen) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_size: EVP_MD_CTX_get_size failed");
    }

    return digestLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1reset(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {
    ////static const char *functionName = "NativeOSSLImplementation.DIGEST_reset";

    EVP_MD_CTX *mdCtx    = (EVP_MD_CTX *)((intptr_t)digestId);
    int        rc        = 0;

    if (NULL == mdCtx) {
        throwOSSLException(env, 0, "DIGEST_size: The specified mdCtx is null");
        return;
    }

    rc = EVP_DigestInit_ex2(mdCtx, NULL, NULL);
    if (1 != rc) {
        //osslCheckStatus(osslCtx);
        throwOSSLException(env, 0, "DIGEST_reset: EVP_DigestInit_ex2 failed");
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    DIGEST_delete
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_DIGEST_1delete(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong digestId) {
    ////static const char *functionName = "NativeOSSLImplementation.DIGEST_delete";
    EVP_MD_CTX *mdCtx = (EVP_MD_CTX *)((intptr_t)digestId);

    if (NULL != mdCtx) {
        EVP_MD_CTX_free(mdCtx);
        mdCtx = NULL;
    }
}
