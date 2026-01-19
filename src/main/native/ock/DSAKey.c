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
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_base_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>
//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSAKEY_generate
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1generate__JI(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits) {
    static const char *functionName = "NativeInterface.DSAKEY_generate(size)";

    ICC_CTX *ockCtx   = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA *ockDSA   = NULL;
    jlong    dsaKeyId = 0;
    int      rc       = -1;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (numBits <= 0) {
        throwOCKException(
            env, 0,
            "DSA Key generate failed. The input parameter is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return dsaKeyId;
    }
#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DSA numBits=%d", numBits);
    }
#endif
    ockDSA = ICC_DSA_generate_parameters(ockCtx, (int)numBits, NULL, 0, NULL,
                                         NULL, NULL, NULL);
#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DSA ockDSA=%lx", (long)ockDSA);
    }
#endif
    if (ockDSA == NULL) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE Failed to allocated ockDSA");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_DSA_generate_parameters failed");
    } else {
        rc = ICC_DSA_generate_key(ockCtx, ockDSA);
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA rc from ICC_DSA_generate_key=%d", rc);
        }
#endif
        if (rc != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE ICC_DSA_generate_key");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_DSA_generate_key failed");
        } else {
            dsaKeyId = (jlong)((intptr_t)ockDSA);
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA dsaKeyId=%lx", dsaKeyId);
            }
#endif
        }
    }

    if ((ockDSA != NULL) && (dsaKeyId == 0)) {
        ICC_DSA_free(ockCtx, ockDSA);
        ockDSA = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSAKEY_generateParameters
 * Signature: (JI)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1generateParameters(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits) {
    static const char *functionName =
        "NativeInterface.DSAKEY_generateParameters";

    ICC_CTX       *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA          = NULL;
    jbyteArray     parmBytes       = NULL;
    unsigned char *parmBytesNative = NULL;
    jboolean       isCopy          = 0;
    jbyteArray     retParmBytes    = NULL;
    int            size            = -1;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_DSA_DETAIL
        gslogMessage("DETAIL_DSA numBits=%d", (int)numBits);
#endif
    }

    if (numBits <= 0) {
        throwOCKException(
            env, 0,
            "DSA Key generate failed. The input parameter is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retParmBytes;
    }

    ockDSA = ICC_DSA_generate_parameters(ockCtx, (int)numBits, NULL, 0, NULL,
                                         NULL, NULL, NULL);
    if (ockDSA == NULL) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE ICC_DSA_generate_parameters ");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_DSA_generate_parameters failed");
    } else {
        size = ICC_i2d_DSAparams(ockCtx, ockDSA, NULL);
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA size from ICC_i2d_DSAparams=%d", size);
        }
#endif
        if (size < 0) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE ICC_i2d_DSAparams ");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_i2d_DSAparams failed");
        } else {
            parmBytes = (*env)->NewByteArray(env, size);
            if (parmBytes == NULL) {
#ifdef DEBUG_DSA_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_DSA FAILURE Could not allocate parmBytes");
                }
#endif
                throwOCKException(env, 0, "NewByteArray failed");
            } else {
                parmBytesNative =
                    (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                        env, parmBytes, &isCopy));
                if (parmBytesNative == NULL) {
#ifdef DEBUG_DSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DSA FAILURE Could not allocate "
                            "GetPrimitiveArrayCritical");
                    }
#endif
                    throwOCKException(env, 0,
                                      "NULL from GetPrimitiveArrayCritical");
                } else {
                    unsigned char *pBytes = (unsigned char *)parmBytesNative;

                    size = ICC_i2d_DSAparams(ockCtx, ockDSA, &pBytes);
#ifdef DEBUG_DSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DSA size from ICC_i2d_DSAparams=%d", size);
                    }
#endif
                    if (size <= 0) {
#ifdef DEBUG_DSA_DETAIL
                        if (debug) {
                            gslogMessage(
                                "DETAIL_DSA FAILURE ICC_i2d_DSAParams");
                        }
#endif
                        ockCheckStatus(ockCtx);
                        throwOCKException(env, 0, "ICC_i2d_DSAParams failed");
                    } else {
                        retParmBytes = parmBytes;
#ifdef DEBUG_DSA_DATA
                        if (debug) {
                            gslogMessagePrefix("DATA_DSA Parameter Bytes : ");
                            gslogMessageHex((char *)pBytes, 0, size, 0, 0,
                                            NULL);
                        }
#endif
                    }
                }
            }
        }
    }

    if (ockDSA != NULL) {
        ICC_DSA_free(ockCtx, ockDSA);
        ockDSA = NULL;
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
 * Method:    DSAKEY_generate
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1generate__J_3B(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jbyteArray parmBytes) {
    static const char *functionName = "NativeInterface.DSAKEY_generate(parms)";

    ICC_CTX             *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    unsigned char       *parmBytesNative = NULL;
    jboolean             isCopy          = 0;
    ICC_DSA             *ockDSA          = NULL;
    jlong                dsaKeyId        = 0;
    int                  rc              = 0;
    jint                 size            = 0;
    const unsigned char *pBytes          = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (parmBytes == NULL) {
        throwOCKException(env, 0,
                          "DSA Key generate failed. The specified input "
                          "parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return dsaKeyId;
    }
    parmBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, parmBytes, &isCopy));
    if (parmBytesNative == NULL) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_DSA FAILURE Could not allocate "
                "GetPrimitiveArrayCritical");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        size   = (*env)->GetArrayLength(env, parmBytes);
        pBytes = (const unsigned char *)parmBytesNative;
#ifdef DEBUG_DSA_DATA
        if (debug) {
            gslogMessage("DATA_DSA Parameter Bytes size %d=", (int)size);
            gslogMessagePrefix("DATA_DSA Parameter Bytes : ");
            gslogMessageHex((char *)parmBytesNative, 0, (int)size, 0, 0, NULL);
        }
#endif

        ockDSA = ICC_d2i_DSAparams(ockCtx, NULL, &pBytes, size);
        if (ockDSA == NULL) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE NULL from ICC_d2i_DSAparams");
            }
#endif
            throwOCKException(env, 0, "NULL from ICC_d2i_DSAparams");
        } else {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA ockDSA =%lx", (long)ockDSA);
            }
#endif
            rc = ICC_DSA_generate_key(ockCtx, ockDSA);
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA rc=%d", rc);
            }
#endif
            if (rc != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_DSA_DETAIL
                if (debug) {
                    gslogMessage(
                        "DETAIL_DSA FAILURE ICC_DSA_generate_key failed");
                }
#endif
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_DSA_generate_key failed");
            } else {
                dsaKeyId = (jlong)((intptr_t)ockDSA);
#ifdef DEBUG_DSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DSA dsaKeyId=%lx", dsaKeyId);
                }
#endif
            }
        }
    }

    if (parmBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, parmBytes, parmBytesNative,
                                              0);
    }

    if ((ockDSA != NULL) && (dsaKeyId == 0)) {
        ICC_DSA_free(ockCtx, ockDSA);
        ockDSA = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSAKEY_createPrivateKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1createPrivateKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray privateKeyBytes) {
    static const char *functionName = "NativeInterface.DSAKEY_createPrivateKey";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA         = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    jlong          dsaKeyId       = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (privateKeyBytes == NULL) {
        throwOCKException(env, 0,
                          "The specified DSA Private Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return dsaKeyId;
    }
    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, privateKeyBytes, &isCopy));
    if (keyBytesNative == NULL) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE to allocate keyBytesNative ");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        const unsigned char *pBytes = (const unsigned char *)keyBytesNative;
        jint size = (*env)->GetArrayLength(env, privateKeyBytes);
#ifdef DEBUG_DSA_DATA
        if (debug) {
            gslogMessage("DATA_DSA privateKeyBytes size=%d", (int)size);
            gslogMessagePrefix("DATA_DSA PrivateKeyBytes : ");
            gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
        }
#endif

        ockDSA = ICC_d2i_DSAPrivateKey(ockCtx, NULL, &pBytes, (long)size);
        if (ockDSA == NULL) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE ICC_d2i_DSAPrivateKey ");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_d2i_DSAPrivateKey failed");
        } else {
            dsaKeyId = (jlong)((intptr_t)ockDSA);
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA dsaKeyId=%lx", (long)dsaKeyId);
            }
#endif
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes,
                                              keyBytesNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSAKEY_createPublicKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1createPublicKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray publicKeyBytes) {
    static const char *functionName = "NativeInterface.DSAKEY_createPublicKey";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA         = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    jlong          dsaKeyId       = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (publicKeyBytes == NULL) {
        throwOCKException(env, 0,
                          "The specified DSA Public Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return dsaKeyId;
    }
    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, publicKeyBytes, &isCopy));
    if (keyBytesNative == NULL) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE to allocate keyBytesNative ");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        const unsigned char *pBytes = (const unsigned char *)keyBytesNative;
        jint                 size = (*env)->GetArrayLength(env, publicKeyBytes);
#ifdef DEBUG_DSA_DATA
        if (debug) {
            gslogMessage("DATA_DSA publicKeyBytes size=%d", (int)size);
            gslogMessagePrefix("DATA_DSA PublicKeyBytes : ");
            gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
        }
#endif

        ockDSA = ICC_d2i_DSAPublicKey(ockCtx, NULL, &pBytes, (long)size);
        if (ockDSA == NULL) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE ICC_d2i_DSAPublicKey ");
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_d2i_DSAPublicKey failed");
        } else {
            dsaKeyId = (jlong)((intptr_t)ockDSA);
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA dsaKeyId=%lx", (long)dsaKeyId);
            }
#endif
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes,
                                              keyBytesNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return dsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSAKEY_getParameters
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1getParameters(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dsaKeyId) {
    static const char *functionName = "NativeInterface.DSAKEY_getParameters";

    ICC_CTX       *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA          = (ICC_DSA *)((intptr_t)dsaKeyId);
    jbyteArray     parmBytes       = NULL;
    unsigned char *parmBytesNative = NULL;
    jboolean       isCopy          = 0;
    int            size            = 0;
    jbyteArray     retParmBytes    = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockDSA == NULL) {
        throwOCKException(env, 0,
                          "The specified DSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retParmBytes;
    }
    size = ICC_i2d_DSAparams(ockCtx, ockDSA, NULL);
#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DSA size=%d", (int)size);
    }
#endif
    if (size < 0) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE ICC_i2d_DSAparams ");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_DSAparams failed");
    } else {
        parmBytes = (*env)->NewByteArray(env, size);
        if (parmBytes == NULL) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE NewByteArray");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            parmBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, parmBytes, &isCopy));
            if (parmBytesNative == NULL) {
#ifdef DEBUG_DSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DSA FAILURE paramBytesNative ");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                unsigned char *pBytes = (unsigned char *)parmBytesNative;

                size = ICC_i2d_DSAparams(ockCtx, ockDSA, &pBytes);
#ifdef DEBUG_DSA_DATA
                if (debug) {
                    gslogMessage("DATA_DSA size=%d", (int)size);
                    gslogMessagePrefix("Parameter Bytes : ");
                    gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
                }
#endif
                if (size <= 0) {
#ifdef DEBUG_DSA_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_DSA FAILURE ICC_i2d_DSAParms");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_i2d_DSAParams failed");
                } else {
                    retParmBytes = parmBytes;
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
 * Method:    DSAKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1getPrivateKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dsaKeyId) {
    static const char *functionName =
        "NativeInterface.DSAKEY_getPrivateKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA         = (ICC_DSA *)((intptr_t)dsaKeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockDSA == NULL) {
        throwOCKException(env, 0,
                          "The specified DSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }
#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DSA dsaKeyId=%lx", (long)dsaKeyId);
    }
#endif

    size = ICC_i2d_DSAPrivateKey(ockCtx, ockDSA, NULL);
#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DSA size=%d", (int)size);
    }
#endif
    if (size <= 0) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE ICC_i2d_DSAPrivateKey");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_DSAPrivateKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE keyBytes");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
#ifdef DEBUG_DSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DSA FAILURE keyBytesNative");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                unsigned char *pBytes = (unsigned char *)keyBytesNative;

                size = ICC_i2d_DSAPrivateKey(ockCtx, ockDSA, &pBytes);
#ifdef DEBUG_DSA_DATA
                if (debug) {
                    gslogMessage("DATA_DSA private key bytes size=%d",
                                 (int)size);
                    gslogMessagePrefix("DSA_DATA PrivateKey Bytes : ");
                    gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
                }
#endif
                if (size <= 0) {
#ifdef DEBUG_DSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DSA FAILURE ICC_i2d_DSAPrivateKey");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_i2d_DSAPrivateKey failed");
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

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSAKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dsaKeyId) {
    static const char *functionName =
        "NativeInterface.DSAKEY_getPublicKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA       *ockDSA         = (ICC_DSA *)((intptr_t)dsaKeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockDSA == NULL) {
        throwOCKException(env, 0,
                          "The specified DSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }
#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_DSA dsaKeyId=%lx", (long)dsaKeyId);
    }
#endif

    size = ICC_i2d_DSAPublicKey(ockCtx, ockDSA, NULL);
#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("size=%d", (int)size);
    }
#endif
    if (size <= 0) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE ICC_i2d_DSAPrivateKey");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_DSAPublicKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA FAILURE NewByteArray");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
#ifdef DEBUG_DSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_DSA FAILURE keyBytesNative ");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                unsigned char *pBytes = (unsigned char *)keyBytesNative;

                size = ICC_i2d_DSAPublicKey(ockCtx, ockDSA, &pBytes);
                if (size <= 0) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_DSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_DSA FAILURE ICC_i2d_DSAPublicKey ");
                    }
#endif
                    throwOCKException(env, 0, "ICC_i2d_DSAPublicKey failed");
                } else {
                    retKeyBytes = keyBytes;
#ifdef DEBUG_DSA_DETAIL
                    if (debug) {
                        gslogMessage("size=%d", (int)size);
                        gslogMessagePrefix("Public Key bytes : ");
                        gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0,
                                        NULL);
                    }
#endif
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

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return keyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    DSAKEY_createPKey
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1createPKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dsaKeyId) {
    static const char *functionName = "NativeInterface.DSAKEY_createPKey";

    ICC_CTX      *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA      *ockDSA  = (ICC_DSA *)((intptr_t)dsaKeyId);
    ICC_EVP_PKEY *ockPKey = NULL;
    jlong         pkeyId  = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockDSA == NULL) {
        throwOCKException(env, 0,
                          "The specified DSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return pkeyId;
    }

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if (ockPKey == NULL) {
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_DSA FAILURE ICC_EVP_PKEY_new");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
        int rc = ICC_EVP_PKEY_set1_DSA(ockCtx, ockPKey, ockDSA);
#ifdef DEBUG_DSA_DETAIL
        if (debug) {
            gslogMessage("rc from ICC_EVP_PKEY_set1_DSA=%d", rc);
        }
#endif
        if (rc != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_DSA FAILURE ICC_EVP_PKEY_set1_DSA failed rc %d ",
                    rc);
            }
#endif
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_PKEY_set1_DSA failed");
        } else {
            pkeyId = (jlong)((intptr_t)ockPKey);
#ifdef DEBUG_DSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_DSA pkeyId=%lx", pkeyId);
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
 * Method:    DSAKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_DSAKEY_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong dsaKeyId) {
    static const char *functionName = "NativeInterface.DSAKEY_delete";

    ICC_CTX *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_DSA *ockDSA = (ICC_DSA *)((intptr_t)dsaKeyId);

    if (debug) {
        gslogFunctionEntry(functionName);
    }

#ifdef DEBUG_DSA_DETAIL
    if (debug) {
        gslogMessage("ockDSA=%lx", (long)ockDSA);
    }
#endif
    if (ockDSA != NULL) {
        ICC_DSA_free(ockCtx, ockDSA);
        ockDSA = NULL;
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }
}
