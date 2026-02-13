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
#include <memory.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_base_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_generate
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1generate__JI(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits) {
    static const char *functionName = "NativeInterface.DHKEY_generate(size)";

    ICC_CTX *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH  *ockDH   = NULL;
    jlong    dhKeyId = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_DH_DETAIL
        gslogMessage("DETAIL_DH numBits=%d", (int)numBits);
#endif
    }

    /* TODO: how do we know what to pass for the third parameter? */
    // fprintf(stderr, "about to call ICC_DH_generate_parameters\n");
    ockDH = ICC_DH_generate_parameters(ockCtx, (int)numBits, 2, NULL, NULL);
    // fprintf(stderr, "returned from ICC_DH_generate_parameters\n");
    if (ockDH == NULL) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE ICC_DH_generate_parameters");
        }
#endif
        throwOCKException(env, 0, "ICC_DH_generate_parameters failed");
    } else {
        int rc;
        rc = ICC_DH_generate_key(ockCtx, ockDH);
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_DH_generate_key rc=d", rc);
            }
#endif
            throwOCKException(env, 0, "ICC_DH_generate_key failed");
        } else {
            dhKeyId = (jlong)((intptr_t)ockDH);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH returning dhKeyId=%lx", (long)dhKeyId);
            }
#endif
        }
    }

    if ((ockDH != NULL) && (dhKeyId == 0)) {
        ICC_DH_free(ockCtx, ockDH);
        ockDH = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dhKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_generateParameters
 * Signature: (JI)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1generateParameters(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits) {
    static const char *functionName =
        "NativeInterface.DHKEY_generateParameters";

    ICC_CTX       *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH        *ockDH           = NULL;
    jbyteArray     parmBytes       = NULL;
    unsigned char *parmBytesNative = NULL;
    jboolean       isCopy          = 0;
    jbyteArray     retParmBytes    = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_DH_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DH ICC_DH_generate_parameters");
    }
#endif

    ockDH = ICC_DH_generate_parameters(ockCtx, (int)numBits, 2, NULL, NULL);
    if (ockDH == NULL) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE ICC_DH_generate_parameters");
        }
#endif
        throwOCKException(env, 0, "ICC_DH_generate_parameters failed");
    } else {
        int size = ICC_i2d_DHparams(ockCtx, ockDH, NULL);
        if (size < 0) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_i2d_DHparams size=%d",
                             (int)size);
            }
#endif
            throwOCKException(env, 0, "ICC_i2d_DHparams failed");
        } else {
            parmBytes = (*env)->NewByteArray(env, size);
            if (parmBytes == NULL) {
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE NewByteArray allocation");
                }
#endif
                throwOCKException(env, 0, "NewByteArray failed");
            } else {
                parmBytesNative =
                    (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                        env, parmBytes, &isCopy));
                if (parmBytesNative == NULL) {
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DH FAILURE paramBytesNative allocation");
                    }
#endif
                    throwOCKException(env, 0,
                                      "NULL from GetPrimitiveArrayCritical");
                } else {
                    unsigned char *pBytes = (unsigned char *)parmBytesNative;

                    size = ICC_i2d_DHparams(ockCtx, ockDH, &pBytes);
                    if (size <= 0) {
                        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_DH FAILURE ICC_i2d_DHparams size=%d",
                                (int)size);
                        }
#endif
                        throwOCKException(env, 0, "ICC_i2d_DHParams failed");
                    } else {
#ifdef DEBUG_DH_DATA
                        if (debug) {
                            gslogMessage("DETAIL_DH ICC_i2d_DHparams size=%d",
                                         (int)size);
                            gslogMessagePrefix("DATA_DH parmBytes : ");
                            gslogMessageHex((char *)parmBytes, 0, size, 0, 0,
                                            NULL);
                        }
#endif
                        retParmBytes = parmBytes;
                    }
                }
            }
        }
    }

    if (ockDH != NULL) {
        ICC_DH_free(ockCtx, ockDH);
        ockDH = NULL;
    }

    if (parmBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, parmBytes, parmBytesNative,
                                              0);
    }

    if ((parmBytes != NULL) && (retParmBytes == NULL)) {
        (*env)->DeleteLocalRef(env, parmBytes);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retParmBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_generate
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1generate__J_3B(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray parmBytes) {
    static const char *functionName = "NativeInterface.DHKEY_generate(parms)";

    ICC_CTX       *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    unsigned char *parmBytesNative = NULL;
    jboolean       isCopy          = 0;
    ICC_DH        *ockDH           = NULL;
    jlong          dhKeyId         = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (parmBytes == NULL) {
        throwOCKException(env, 0, "DH Key parameter bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return dhKeyId;
    }

    parmBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, parmBytes, &isCopy));
    if (parmBytesNative == NULL) {
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE paramBytesNative allocation");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        jint                 size   = (*env)->GetArrayLength(env, parmBytes);
        const unsigned char *pBytes = (const unsigned char *)parmBytesNative;
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_DH DHKey_generate ICC_d2i_DHparams(ockCtx) : %d",
                (long)ockCtx);
            gslogMessage(
                "DETAIL_DH DHKey_generate(params) ICC_d2i_DHparams(NULL)");
#ifdef DEBUG_DH_DATA
            gslogMessagePrefix(
                "DETAIL_DH DHKey_generate ICC_d2i_DHparams(pBytes) : ");
            gslogMessageHex((char *)pBytes, 0, size, 0, 0, NULL);
#endif
            gslogMessagePrefix(
                "DETAIL_DH DHKey_generate ICC_d2i_DHparams(size) : %d\n",
                (int)size);
        }
#endif

        ockDH = ICC_d2i_DHparams(ockCtx, NULL, &pBytes, size);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_DH DHKey_generate ICC_d2i_DHparams returned : %d\n",
                (long)ockDH);
        }
#endif
        if (ockDH == NULL) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_d2i_DHparams");
            }
#endif
            throwOCKException(env, 0, "NULL from ICC_d2i_DHparams");
        } else {
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_DH DHKey_generate ICC_DH_generate_key(ockCtx) : %d",
                    (long)ockCtx);
                gslogMessage(
                    "DETAIL_DH DHKey_generate ICC_DH_generate_key(ockDH) : %d",
                    (long)ockDH);
            }
#endif
            int rc = ICC_DH_generate_key(ockCtx, ockDH);
            if (rc != ICC_OSSL_SUCCESS) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE ICC_DH_generate_key rc=%d",
                                 rc);
                }
#endif
                throwOCKException(env, 0, "ICC_DH_generate_key failed");
            } else {
                dhKeyId = (jlong)((intptr_t)ockDH);
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH returning dhKeyId=%lx",
                                 (long)ockDH);
                }
#endif
            }
        }
    }

    if (parmBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, parmBytes, parmBytesNative,
                                              0);
    }

    if ((ockDH != NULL) && (dhKeyId == 0)) {
        ICC_DH_free(ockCtx, ockDH);
        ockDH = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dhKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_createPrivateKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1createPrivateKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray privateKeyBytes) {
    static const char *functionName = "NativeInterface.DHKEY_createPrivateKey";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH        *ockDH          = NULL;
    ICC_EVP_PKEY  *ockPKey        = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    jlong          dhKeyId        = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (privateKeyBytes == NULL) {
        throwOCKException(env, 0,
                          "The specified DH Private Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return dhKeyId;
    }

    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, privateKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE keyBytesNative allocation");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        const unsigned char *pBytes = (const unsigned char *)keyBytesNative;
        jint size = (*env)->GetArrayLength(env, privateKeyBytes);

        ockPKey = ICC_EVP_PKEY_new(ockCtx);
        if (NULL == ockPKey) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_new");
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
        } else {
            ICC_EVP_PKEY *ret = ICC_d2i_PrivateKey(
                ockCtx, ICC_EVP_PKEY_DH, &ockPKey, &pBytes, (long)size);
            if (ret == NULL) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE ICC_d2i_PrivateKey");
                }
#endif
                throwOCKException(env, 0, "ICC_d2i_PrivateKey failed");
            } else {
                ockDH = ICC_EVP_PKEY_get1_DH(ockCtx, ockPKey);
                if (ockDH == NULL) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_get1_DH");
                    }
#endif
                    throwOCKException(env, 0, "ICC_EVP_PKEY_get1_DH failed");
                } else {
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_DH returning dhKeyId=%lx",
                                     (long)ockDH);
                    }
#endif
                    dhKeyId = (jlong)((intptr_t)ockDH);
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes,
                                              keyBytesNative, 0);
    }
    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dhKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_createPublicKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1createPublicKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray publicKeyBytes) {
    static const char *functionName = "NativeInterface.DHKEY_createPublicKey";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH        *ockDH          = NULL;
    ICC_EVP_PKEY  *ockPKey        = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    jlong          dhKeyId        = 0;
    unsigned char *pBytes         = NULL;
    jint           size           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (publicKeyBytes == NULL) {
        throwOCKException(env, 0,
                          "The specified DH Public Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return dhKeyId;
    }

    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, publicKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE keyBytesNative allocation");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        pBytes = (unsigned char *)keyBytesNative;
        size   = (*env)->GetArrayLength(env, publicKeyBytes);

        ockPKey = ICC_EVP_PKEY_new(ockCtx);
        if (NULL == ockPKey) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_new");
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
        } else {
            ICC_EVP_PKEY *ret = ICC_d2i_PUBKEY(
                ockCtx, &ockPKey, (const unsigned char **)&pBytes, (long)size);
            if (ret == NULL) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_new");
                }
#endif
                throwOCKException(env, 0, "ICC_d2i_PublicKey failed");
            } else {
                ockDH = ICC_EVP_PKEY_get1_DH(ockCtx, ockPKey);
                if (ockDH == NULL) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_get1_DH");
                    }
#endif
                    throwOCKException(env, 0, "ICC_EVP_PKEY_get1_DH failed");
                } else {
                    dhKeyId = (jlong)((intptr_t)ockDH);
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_DH returning dhKeyId=%lx",
                                     (long)ockDH);
                    }
#endif
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes,
                                              keyBytesNative, 0);
    }

    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dhKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_getParameters
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1getParameters(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dhKeyId) {
    static const char *functionName = "NativeInterface.DHKEY_getParameters";

    ICC_CTX       *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH        *ockDH           = (ICC_DH *)((intptr_t)dhKeyId);
    jbyteArray     parmBytes       = NULL;
    unsigned char *parmBytesNative = NULL;
    jboolean       isCopy          = 0;
    int            size            = 0;
    jbyteArray     retParmBytes    = NULL;
    unsigned char *pBytes          = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockDH == NULL) {
        throwOCKException(env, 0,
                          "The specified DH Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retParmBytes;
    }

    size = ICC_i2d_DHparams(ockCtx, ockDH, NULL);
    if (size < 0) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE ICC_i2d_DHparams size=%d",
                         (int)size);
        }
#endif
        throwOCKException(env, 0, "ICC_i2d_DHparams failed");
    } else {
        parmBytes = (*env)->NewByteArray(env, size);
        if (parmBytes == NULL) {
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE parmBytes allocation");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            parmBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, parmBytes, &isCopy));
            if (parmBytesNative == NULL) {
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE parmBytesNative");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                pBytes = (unsigned char *)parmBytesNative;

                size = ICC_i2d_DHparams(ockCtx, ockDH, &pBytes);
                if (size <= 0) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DH FAILURE ICC_i2d_DHparams size=%d", size);
                    }
#endif
                    throwOCKException(env, 0, "ICC_i2d_DHParams failed");
                } else {
                    retParmBytes = parmBytes;
#ifdef DEBUG_DH_DATA
                    if (debug) {
                        gslogMessagePrefix("DETAIL_DH parameter Bytes :");
                        gslogMessageHex((char *)parmBytes, 0, size, 0, 0, NULL);
                    }
#endif
                }
            }
        }
    }

    if (parmBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, parmBytes, parmBytesNative,
                                              0);
    }

    if ((parmBytes != NULL) && (retParmBytes == NULL)) {
        (*env)->DeleteLocalRef(env, parmBytes);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retParmBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1getPrivateKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dhKeyId) {
    static const char *functionName =
        "NativeInterface.DHKEY_getPrivateKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH        *ockDH          = (ICC_DH *)((intptr_t)dhKeyId);
    ICC_EVP_PKEY  *ockPKey        = NULL;
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;
    unsigned char *pBytes      = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockDH == NULL) {
        throwOCKException(env, 0,
                          "The specified DH Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if (NULL == ockPKey) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_new");
        }
#endif
        throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
        ICC_EVP_PKEY_set1_DH(ockCtx, ockPKey, ockDH);
        size = ICC_i2d_PrivateKey(ockCtx, ockPKey, NULL);

        if (size <= 0) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_i2d_PrivateKey size=%d",
                             size);
            }
#endif
            throwOCKException(env, 0, "ICC_i2d_DHPrivateKey failed");
        } else {
            keyBytes = (*env)->NewByteArray(env, size);
            if (keyBytes == NULL) {
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE keyBytes allocation");
                }
#endif
                throwOCKException(env, 0, "NewByteArray failed");
            } else {
                keyBytesNative =
                    (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                        env, keyBytes, &isCopy));
                if (keyBytesNative == NULL) {
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DH FAILURE keyBytesNative allocation");
                    }
#endif
                    throwOCKException(env, 0,
                                      "NULL from GetPrimitiveArrayCritical");
                } else {
                    pBytes = (unsigned char *)keyBytesNative;

                    size = ICC_i2d_PrivateKey(ockCtx, ockPKey, &pBytes);
                    if (size <= 0) {
                        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_DH FAILURE ICC_i2d_PrivateKey size=%d",
                                size);
                        }
#endif
                        throwOCKException(env, 0,
                                          "ICC_i2d_DHPrivateKey failed");
                    } else {
                        retKeyBytes = keyBytes;
#ifdef DEBUG_DH_DATA
                        if (debug) {
                            gslogMessagePrefix("DETAIL_DH key Bytes :");
                            gslogMessageHex((char *)keyBytes, 0, size, 0, 0,
                                            NULL);
                        }
#endif
                    }
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
    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dhKeyId) {
    static const char *functionName = "NativeInterface.DHKEY_getPublicKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH        *ockDH          = (ICC_DH *)((intptr_t)dhKeyId);
    ICC_EVP_PKEY  *ockPKey        = NULL;
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;
    unsigned char *pBytes      = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockDH == NULL) {
        throwOCKException(env, 0,
                          "The specified DH Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if (NULL == ockPKey) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_new");
        }
#endif
        throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
        ICC_EVP_PKEY_set1_DH(ockCtx, ockPKey, ockDH);
        size = ICC_i2d_PUBKEY(ockCtx, ockPKey, NULL);

        if (size <= 0) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_i2d_PUBKEY size=%d", size);
            }
#endif
            throwOCKException(env, 0, "ICC_i2d_DHPublicKey failed");
        } else {
            keyBytes = (*env)->NewByteArray(env, size);
            if (keyBytes == NULL) {
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE keyBytes allocation");
                }
#endif
                throwOCKException(env, 0, "NewByteArray failed");
            } else {
                keyBytesNative =
                    (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                        env, keyBytes, &isCopy));
                if (keyBytesNative == NULL) {
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DH FAILURE keyBytesNative allocation");
                    }
#endif
                    throwOCKException(env, 0,
                                      "NULL from GetPrimitiveArrayCritical");
                } else {
                    pBytes = (unsigned char *)keyBytesNative;

                    size = ICC_i2d_PUBKEY(ockCtx, ockPKey, &pBytes);

                    if (size <= 0) {
                        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_DH FAILURE ICC_i2d_PUBKEY size=%d",
                                size);
                        }
#endif
                        throwOCKException(env, 0, "ICC_i2d_DHPublicKey failed");
                    } else {
                        retKeyBytes = keyBytes;
#ifdef DEBUG_DH_DATA
                        if (debug) {
                            gslogMessagePrefix("DETAIL_DH key Bytes :");
                            gslogMessageHex((char *)keyBytes, 0, size, 0, 0,
                                            NULL);
                        }
#endif
                    }
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

    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return keyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_createPKey
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1createPKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dhKeyId) {
    static const char *functionName = "NativeInterface.DHKEY_createPKey";

    ICC_CTX      *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH       *ockDH   = (ICC_DH *)((intptr_t)dhKeyId);
    ICC_EVP_PKEY *ockPKey = (ICC_EVP_PKEY *)((intptr_t)dhKeyId);
    jlong         pkeyId  = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockDH == NULL) {
        throwOCKException(env, 0,
                          "The specified DH Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return pkeyId;
    }

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if (ockPKey == NULL) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_new");
        }
#endif
        throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
        int rc = ICC_EVP_PKEY_set1_DH(ockCtx, ockPKey, ockDH);
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_EVP_PKEY_set1_DH rc=%d",
                             rc);
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_set1_DH failed");
        } else {
            pkeyId = (jlong)((intptr_t)ockPKey);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH pkeyId=%lx", (long)pkeyId);
            }
#endif
        }
    }

    if ((ockPKey != NULL) && (pkeyId == 0)) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return pkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_computeDHSecret
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1computeDHSecret(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong pubKeyId,
    jlong privKeyId) {
    static const char *functionName = "NativeInterface.DHKEY_computeDHSecret";

    ICC_CTX       *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH        *ockPubDHKey       = (ICC_DH *)((intptr_t)pubKeyId);
    ICC_DH        *ockPrivDHKey      = (ICC_DH *)((intptr_t)privKeyId);
    ICC_BIGNUM    *ockPubDHKeyBN     = NULL;
    jbyteArray     secretBytes       = NULL;
    unsigned char *secretBytesNative = NULL;
    jbyteArray     retSecretBytes    = NULL;
    unsigned char *bbbuf             = NULL;
    jboolean       isCopy            = 0;
    int            lena              = 0;
    int            keylen            = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockPubDHKey == NULL) || (ockPrivDHKey == NULL)) {
        throwOCKException(env, 0,
                          "The specified DH Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retSecretBytes;
    }

    keylen =
        ICC_BN_num_bytes(ockCtx, ICC_DH_get_PublicKey(ockCtx, ockPubDHKey));
    if (keylen <= 0) {
        ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DH FAILURE ICC_BN_num_bytes keylen=%d",
                         keylen);
        }
#endif
        throwOCKException(env, 0, "ICC_BN_num_bytes failed");
    } else {
        bbbuf = (unsigned char *)malloc(keylen);
        /* Don't forget the save the REAL length of the buffer ... */
        keylen = ICC_BN_bn2bin(
            ockCtx, ICC_DH_get_PublicKey(ockCtx, ockPubDHKey), bbbuf);
        if (keylen <= 0) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DH FAILURE ICC_BN_bn2bin keylen=%d",
                             keylen);
            }
#endif
            throwOCKException(env, 0, "ICC_BN_bn2bin failed");
        } else {
            /* This form is a big endian byte stream, and should be portable */

            /*
             Now try to put them back into the DH structure.
             Note that in THIS case, all this is unnecessary, but in most
             applications you'd have to transport the public key between
             applications. Note, you have to transport BOTH the key and
             the length of the key.
             */
            /* We pass in NULL, rather than allocate our own ICC_BIGNUM */
            ockPubDHKeyBN = ICC_BN_bin2bn(ockCtx, bbbuf, keylen, NULL);
            if (ockPubDHKeyBN == NULL) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DH FAILURE ICC_BN_bn2bin keylen=%d",
                                 keylen);
                }
#endif
                throwOCKException(env, 0, "ICC_BN_bin2bn failed");
            } else {
                secretBytes = (*env)->NewByteArray(env, keylen);
                if (secretBytes == NULL) {
#ifdef DEBUG_DH_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DH FAILURE secretBytes allocation");
                    }
#endif
                    throwOCKException(env, 0, "NewByteArray failed");
                } else {
                    secretBytesNative =
                        (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                            env, secretBytes, &isCopy));
                    if (secretBytesNative == NULL) {
#ifdef DEBUG_DH_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_DH FAILURE secretBytesNative "
                                "allocation");
                        }
#endif
                        throwOCKException(
                            env, 0, "NULL from GetPrimitiveArrayCritical");
                    } else {
                        unsigned char *pBytes =
                            (unsigned char *)secretBytesNative;

                        lena = ICC_DH_compute_key(ockCtx, pBytes, ockPubDHKeyBN,
                                                  ockPrivDHKey);
                        if (lena == -(ICC_ERROR_FLAG)) {
                            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                            if (debug) {
                                gslogMessage(
                                    "DETAIL_DH FAILURE ICC_DH_compute_key=%d",
                                    lena);
                            }
#endif
                            throwOCKException(env, 0,
                                              "ICC_DH_compute_key failed");
                        } else {
#ifdef DEBUG_DH_DETAIL
                            if (debug) {
                                gslogMessage(
                                    "DETAIL_DH lena from ICC_DH_compute_key "
                                    "lena==%d",
                                    lena);
                            }
#endif
                            /* OCK sometimes computes secrets that are smaller
                               than the key size; pad the leading bytes with
                               zero to get the length to keylen
                             */
                            if (lena < keylen) {
                                int diff = keylen - lena;
                                int k    = 0;
#ifdef DEBUG_DH_DETAIL
                                if (debug) {
                                    gslogMessage("DETAIL_DH lena < keylen");
                                }
#endif
                                memmove(pBytes + diff, pBytes, lena);
                                for (k = 0; k < diff; k++) {
                                    pBytes[k] = 0x0;
                                }

                            } else if (lena > keylen) {
#ifdef DEBUG_DH_DETAIL
                                if (debug) {
                                    gslogMessage(
                                        "DETAIL_DH lena greater than keylen; "
                                        "Redo the secret");
                                }
#endif
                                /* Redo the secret. Last time we chopped the
                                   last byte we need to look at optimizing and
                                   allocate a little bit more the first time if
                                   possible
                                   */

                                if (secretBytesNative != NULL) {
                                    (*env)->ReleasePrimitiveArrayCritical(
                                        env, secretBytes, secretBytesNative, 0);
                                }
                                if (secretBytes != NULL) {
                                    (*env)->DeleteLocalRef(env, secretBytes);
                                }
                                /* Redo the secret with more memory */
                                secretBytes = (*env)->NewByteArray(env, lena);
                                if (secretBytes == NULL) {
#ifdef DEBUG_DH_DETAIL
                                    if (debug) {
                                        gslogMessage(
                                            "DETAIL_DH FAILURE secretBytes");
                                    }
#endif
                                    throwOCKException(env, 0,
                                                      "NewByteArray failed "
                                                      "during recomputation");
                                } else {
                                    secretBytesNative =
                                        (unsigned char
                                             *)((*env)
                                                    ->GetPrimitiveArrayCritical(
                                                        env, secretBytes,
                                                        &isCopy));
                                    if (secretBytesNative == NULL) {
#ifdef DEBUG_DH_DETAIL
                                        if (debug) {
                                            gslogMessage(
                                                "DETAIL_DH FAILURE "
                                                "secretBytesNative allocation");
                                        }
#endif
                                        throwOCKException(
                                            env, 0,
                                            "NULL from "
                                            "GetPrimitiveArrayCritical");
                                    } else {
                                        unsigned char *pBytes =
                                            (unsigned char *)secretBytesNative;

                                        lena = ICC_DH_compute_key(
                                            ockCtx, pBytes, ockPubDHKeyBN,
                                            ockPrivDHKey);
                                        if (lena == -(ICC_ERROR_FLAG)) {
                                            ockCheckStatus(ockCtx);
#ifdef DEBUG_DH_DETAIL
                                            if (debug) {
                                                gslogMessage(
                                                    "DETAIL_DH FAILURE "
                                                    "ICC_DH_compute_key "
                                                    "lena=%d",
                                                    lena);
                                            }
#endif
                                            throwOCKException(
                                                env, 0,
                                                "ICC_DH_compute_key failed");
                                        } else {
                                            retSecretBytes = secretBytes;
#ifdef DEBUG_DH_DATA
                                            if (debug) {
                                                gslogMessagePrefix(
                                                    "DETAIL_DH key Bytes :");
                                                gslogMessageHex(
                                                    (char *)secretBytes, 0,
                                                    lena, 0, 0, NULL);
                                            }
#endif
                                            if (secretBytesNative != NULL) {
                                                (*env)
                                                    ->ReleasePrimitiveArrayCritical(
                                                        env, secretBytes,
                                                        secretBytesNative, 0);
                                            }

                                            if ((secretBytes != NULL) &&
                                                (retSecretBytes == NULL)) {
                                                (*env)->DeleteLocalRef(
                                                    env, secretBytes);
                                            }

                                            if (ockPubDHKeyBN != NULL) {
                                                ICC_BN_clear_free(
                                                    ockCtx, ockPubDHKeyBN);
                                                ockPubDHKeyBN = NULL;
                                            }
                                            FREE_N_NULL(bbbuf);

                                            if (debug) {
                                                gslogFunctionExit(functionName);
                                            }

                                            return retSecretBytes;
                                        }
                                    }
                                }
                            }

                            retSecretBytes = secretBytes;
#ifdef DEBUG_DH_DATA
                            if (debug) {
                                gslogMessagePrefix("DETAIL_DH key Bytes :");
                                gslogMessageHex((char *)secretBytes, 0, lena, 0,
                                                0, NULL);
                            }
#endif
                            if (secretBytesNative != NULL) {
                                (*env)->ReleasePrimitiveArrayCritical(
                                    env, secretBytes, secretBytesNative, 0);
                            }

                            if ((secretBytes != NULL) &&
                                (retSecretBytes == NULL)) {
                                (*env)->DeleteLocalRef(env, secretBytes);
                            }
                            if (ockPubDHKeyBN != NULL) {
                                ICC_BN_clear_free(ockCtx, ockPubDHKeyBN);
                                ockPubDHKeyBN = NULL;
                            }
                            FREE_N_NULL(bbbuf);

                            if (debug) {
                                gslogFunctionExit(functionName);
                            }

                            return retSecretBytes;
                        }
                    }
                }
            }
        }

        FREE_N_NULL(bbbuf);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
    return NULL;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DHKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DHKEY_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dhKeyId) {
    static const char *functionName = "NativeInterface.DHKEY_delete";

    ICC_CTX *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DH  *ockDH  = (ICC_DH *)((intptr_t)dhKeyId);

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_DH_DETAIL
        gslogMessage("DETAIL_DH returning dhKeyId=%lx", (long)dhKeyId);
#endif
    }
    if (ockDH != NULL) {
        ICC_DH_free(ockCtx, ockDH);
        ockDH = NULL;
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }
}
