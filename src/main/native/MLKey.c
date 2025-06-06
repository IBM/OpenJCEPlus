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
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_generate
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1generate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName) {
    static const char *functionName = "NativeInterface.MLKEY_generate";

    const char       *algoChars = NULL;
    ICC_CTX          *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY_CTX *evp_sp    = NULL;
    jlong             mlkeyId   = 0;
    int               nid       = 0;
    int               rv        = ICC_OSSL_SUCCESS;
    ICC_EVP_PKEY     *pa        = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (cipherName == NULL) {
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("cipherName = NULL");
        }
#endif
        throwOCKException(env, 0, "cipherName = NULL");
        return 0;
    }
    if (!(algoChars = (*env)->GetStringUTFChars(env, cipherName, NULL))) {
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("GetStringUTFChars failed %s", cipherName);
        }
#endif
        throwOCKException(env, 0, "GetStringUTFChars failed.");
        return 0;
    }

    nid = ICC_OBJ_txt2nid(ockCtx, algoChars);
    if (!nid) {
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("ICC_OBJ_txt2nid failed- %s", algoChars);
        }
#endif
        throwOCKException(env, 0,
                          "Key generation failed - ICC_OBJ_txt2nid");
        return 0;
    }

    evp_sp = ICC_EVP_PKEY_CTX_new_from_name(ockCtx, NULL, algoChars, NULL);
    if (!evp_sp) {
        evp_sp = ICC_EVP_PKEY_CTX_new_id(ockCtx, nid, NULL);
        if (!evp_sp) {
#ifdef DEBUG_PQC_KEY_DETAIL
            if (debug) {
                gslogMessage("Key generation failed - ICC_EVP_PKEY_CTX_new_id");
            }
#endif
            throwOCKException(
                env, 0, "Key generation failed - ICC_EVP_PKEY_CTX_new_id");
            return 0;
        }
    }

    rv = ICC_EVP_PKEY_keygen_init(ockCtx, evp_sp);
    if (rv != ICC_OSSL_SUCCESS) {
        if (evp_sp) {
            ICC_EVP_PKEY_CTX_free(ockCtx, evp_sp);
        }
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("Key generation failed - ICC_EVP_PKEY_keygen_init");
        }
#endif
        throwOCKException(env, 0, "Key generation failed");
        return 0;
    }

    rv = ICC_EVP_PKEY_keygen(ockCtx, evp_sp, &pa);
    if (rv != ICC_OSSL_SUCCESS) {
        if (evp_sp) {
            ICC_EVP_PKEY_CTX_free(ockCtx, evp_sp);
        }
        if (pa) {
            ICC_EVP_PKEY_free(ockCtx, pa);
        }
        if (debug) {
            gslogMessage("Key generation failed - ICC_EVP_PKEY_keygen");
        }
        throwOCKException(env, 0, "Key generation failed");
        return 0;
    }

    // Test generate keys to make sure they are good
    /* public key */

    int            publen;
    unsigned char *pubdata = NULL;
    unsigned char *pp      = NULL;

    /* binary */
    publen = ICC_i2d_PublicKey(ockCtx, pa, NULL);
    if (publen <= 0) {
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage(
                "ICC_i2d_PublicKey failure. Unable to get public key length\n");
        }
#endif
        throwOCKException(env, 0,
                          "ICC_i2d_PublicKey failure. Unable to get public key "
                          "length for encoding");
    }

    pubdata = malloc(publen);
    pp      = pubdata;
    rv      = ICC_i2d_PublicKey(ockCtx, pa, &pp);

    if (rv <= 0) {
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage(
                "ICC_i2d_PublicKey failure. Unable to encode public key\n");
        }
#endif
        free(pubdata);
        throwOCKException(
            env, 0,
            "ICC_i2d_PublicKey failure. Unable to get encoded public key");
        return mlkeyId;
    }

    /* private key */
    int            privlen;
    unsigned char *privData = NULL;

    privlen  = ICC_i2d_PrivateKey(ockCtx, pa, NULL);
    privData = malloc(privlen);
    pp       = privData;
    rv       = ICC_i2d_PrivateKey(ockCtx, pa, &pp);
    if (rv <= 0) {
        free(pubdata);
        free(privData);
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage(
                "ICC_i2d_PrivateKey failure. Unable to encode private key\n");
        }
#endif
        throwOCKException(
            env, 0,
            "CC_i2d_PrivateKey failure. Unable to get encoded private key");
        return mlkeyId;
    }

    /* verify encodings */
    /* reconstruct keys from encoding */

    int           len;
    ICC_EVP_PKEY *npa = NULL; /* For decoded key */
    pp                = NULL;

    /* public */
    const unsigned char *cpp = pubdata;
    len = publen;

    /* Reconstruct public key from encoding and type */
    npa = ICC_d2i_PublicKey(ockCtx, nid, &npa, &cpp, len);

    if (!npa) {
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("ICC_d2i_PublicKey failure\n");
        }
#endif
        free(pubdata);
        free(privData);
        throwOCKException(
            env, 0,
            "ICC_d2i_PublicKey failure. Unable to reconstruct public key.");
        return mlkeyId;
    }

    if (1 !=
        ICC_EVP_PKEY_cmp(ockCtx, pa, npa)) { /*compare pubkey and decoded key */
        ICC_EVP_PKEY_free(ockCtx, npa);
        free(pubdata);
        free(privData);
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage(
                "warning - public key encode/decode missmatch\n For Alg = %s\n",
                algoChars);
        }
#endif
        throwOCKException(env, 0, "public key encode/decode missmatch");
        return mlkeyId;
    }

    ICC_EVP_PKEY_free(ockCtx, npa);
    free(pubdata);

    pubdata = NULL;
    npa     = NULL;

    /* private */
    cpp  = privData;
    len = privlen;
    npa = ICC_d2i_PrivateKey(ockCtx, nid, &npa, &cpp, len);
    if (!npa) {
        free(privData);
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("ICC_d2i_PrivateKey failure\n");
        }
#endif
        throwOCKException(
            env, 0,
            "ICC_d2i_PrivateKey failure. Unable to reconstruct private key.");
        return mlkeyId;
    }

    if (npa) {
        size_t keylen = ICC_EVP_PKEY_size(ockCtx, pa);
        size_t kl     = ICC_EVP_PKEY_size(ockCtx, npa);
        if (keylen == 0 || kl != keylen) {
            free(privData);
#ifdef DEBUG_PQC_KEY_DETAIL
            if (debug) {
                gslogMessage("warning - key size missmatch %d != %d\n",
                             (int)keylen, (int)kl);
            }
#endif
            throwOCKException(env, 0, "key size missmatch on private key");
            return mlkeyId;
        }
        if (1 != ICC_EVP_PKEY_cmp(ockCtx, pa, npa)) {
            free(privData);
#ifdef DEBUG_PQC_KEY_DETAIL
            if (debug) {
                gslogMessage("warning - private key encode/decode missmatch\n");
            }
#endif
            throwOCKException(env, 0, "private key encode/decode missmatch");
            return mlkeyId;
        }
    }
    ICC_EVP_PKEY_free(ockCtx, npa);
    free(privData);
    privData = NULL;

    if (evp_sp) {
        ICC_EVP_PKEY_CTX_free(ockCtx, evp_sp);
    }
    mlkeyId = (jlong)((intptr_t)pa);

    return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_createPrivateKey
 * Returns:   pointer to Octet encapsulated key
 * Signature: (JLjava/lang/String;[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1createPrivateKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName,
    jbyteArray privateKeyBytes) {
    ICC_CTX             *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY        *ockPKey        = NULL;
    unsigned char       *keyBytesNative = NULL;
    jboolean             isCopy         = 0;
    jlong                mlkeyId        = 0;
    const unsigned char *pBytes         = NULL;
    const char          *algoChars      = NULL;
    size_t               size           = 0;
    int                  nid            = 0;

    if (privateKeyBytes == NULL) {
        throwOCKException(env, 0,
                          "The ML Key Private Key bytes are incorrect.");
        return mlkeyId;
    }

    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, privateKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        pBytes = keyBytesNative;
        size   = (*env)->GetArrayLength(env, privateKeyBytes);
        if (cipherName == NULL) {
#ifdef DEBUG_PQC_KEY_DETAIL
            if (debug) {
                gslogMessage("cipherName = NULL");
            }
#endif
            (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes,
                                                  keyBytesNative, JNI_ABORT);
            return 0;
        }

        if (!(algoChars = (*env)->GetStringUTFChars(env, cipherName, NULL))) {
#ifdef DEBUG_PQC_KEY_DETAIL
            if (debug) {
                gslogMessage("GetStringUTFChars failed %s", cipherName);
            }
#endif
            (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes,
                                                  keyBytesNative, JNI_ABORT);
            return 0;
        }
        nid = ICC_OBJ_txt2nid(ockCtx, algoChars);

        if (!nid) {
            throwOCKException(
                env, 0, "Algorithm not found."); /* Unsupported algorithm */
        } else {
            ockPKey =
                ICC_d2i_PrivateKey(ockCtx, nid, &ockPKey, &pBytes, (long)size);

            if (ockPKey == NULL) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_d2i_PrivateKey failed");
            } else {
                mlkeyId = (jlong)((intptr_t)ockPKey);
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes,
                                              keyBytesNative, JNI_ABORT);
    }

    return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_createPublicKey
 * Return:    BitString encapsulated key
 * Signature: (JLjava/lang/String;[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1createPublicKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName,
    jbyteArray publicKeyBytes) {
    ICC_CTX             *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY        *ockPKey        = NULL;
    unsigned char       *keyBytesNative = NULL;
    jboolean             isCopy         = 0;
    jlong                mlkeyId        = 0;
    const unsigned char *pBytes         = NULL;
    const char          *algoChars      = NULL;
    long                 size           = 0;
    int                  nid            = 0;

    if (publicKeyBytes == NULL) {
        throwOCKException(env, 0, "The MLKEY Key Public bytes are incorrect.");
        return mlkeyId;
    }

    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, publicKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        pBytes = keyBytesNative;
        size   = (*env)->GetArrayLength(env, publicKeyBytes);

        if (!(algoChars = (*env)->GetStringUTFChars(env, cipherName, NULL))) {
#ifdef DEBUG_PQC_KEY_DETAIL
            if (debug) {
                gslogMessage("GetStringUTFChars failed %s", cipherName);
            }
#endif
            (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes,
                                                  keyBytesNative, JNI_ABORT);
            return 0;
        }

        nid = ICC_OBJ_txt2nid(ockCtx, algoChars);

        if (!nid) {
            throwOCKException(
                env, 0, "Algorithm not found."); /* Unsupported algorithm */
        } else {
            ockPKey = ICC_d2i_PublicKey(ockCtx, nid, &ockPKey, &pBytes, size);
            if (ockPKey == NULL) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_d2i_PublicKey failed");
            } else {
                mlkeyId = (jlong)((intptr_t)ockPKey);
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes,
                                              keyBytesNative, JNI_ABORT);
    }

    return mlkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_getPrivateKeyBytes
 * Return:    RAW key - This may change in the future.
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1getPrivateKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkeyId) {
    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY  *ockKey         = (ICC_EVP_PKEY *)((intptr_t)mlkeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size           = 0;
    jbyteArray     retKeyBytes    = NULL;
    unsigned char *pBytes         = NULL;
    int            rc             = ICC_OSSL_SUCCESS;

    if (NULL == ockKey) {
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("NULL == ockKey");
        }
#endif

        throwOCKException(env, 0, "The Key identifier is incorrect.");
        return retKeyBytes;
    }

    size = ICC_i2d_PrivateKey(ockCtx, ockKey, NULL);

    if (size <= 0) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_PQC_KEY_DETAIL
        if (debug) {
            gslogMessage("ICC_i2d_PrivateKey failed");
        }
#endif
        throwOCKException(env, 0, "ICC_i2d_PrivateKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
#ifdef DEBUG_PQC_KEY_DETAIL
            if (debug) {
                gslogMessage("NewByteArray failed");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
#ifdef DEBUG_PQC_KEY_DETAIL
                if (debug) {
                    gslogMessage("NULL from GetPrimitiveArrayCritical");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                pBytes = keyBytesNative;

                rc = ICC_i2d_PrivateKey(ockCtx, ockKey, &pBytes);
                if (rc <= 0) {
#ifdef DEBUG_PQC_KEY_DETAIL
                    if (debug) {
                        gslogMessage("ICC_i2d_PrivateKey failed");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_i2d_PrivateKey failed");
                } else {
                    retKeyBytes = keyBytes;
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
    }

    if ((keyBytes != NULL) && (retKeyBytes == NULL)) {
        (*env)->DeleteLocalRef(env, keyBytes);
    }

    return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_getPublicKeyBytes
 * Return:    RAW key
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkeyId) {
    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY  *ockKey         = (ICC_EVP_PKEY *)((intptr_t)mlkeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    long           size           = 0;
    unsigned char *pBytes         = NULL;
    jbyteArray     retKeyBytes    = NULL;
    int            rc             = ICC_OSSL_SUCCESS;

    if (ockKey == NULL) {
        return retKeyBytes;
    }

    size = ICC_i2d_PublicKey(ockCtx, ockKey, NULL);
    if (size <= 0) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_PublicKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                pBytes = keyBytesNative;

                rc = ICC_i2d_PublicKey(ockCtx, ockKey, &pBytes);
                if (rc <= 0) {
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_i2d_PublicKey failed");
                } else {
                    retKeyBytes = keyBytes;
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
    }

    if ((keyBytes != NULL) && (retKeyBytes == NULL)) {
        (*env)->DeleteLocalRef(env, keyBytes);
    }

    return keyBytes;
}

//============================================================================
/* NOTE:
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    MLKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_MLKEY_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong mlkeyId) {
    ICC_CTX      *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY *ockKey = (ICC_EVP_PKEY *)((intptr_t)mlkeyId);

    if (ockKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockKey);
        ockKey = NULL;
    }
}
