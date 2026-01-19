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
 * Method:    RSAKEY_generate
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1generate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits, jlong e) {
    static const char *functionName = "NativeInterface.RSAKEY_generate";

    ICC_CTX          *ockCtx   = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA          *ockRSA   = NULL;
    ICC_EVP_PKEY     *ockPKey  = NULL;
    ICC_EVP_PKEY_CTX *pctx     = NULL;
    jlong             rsaKeyId = 0;
    int               ret      = 0;
    char              bitStr[32];
    char              expStr[32];

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    pctx = ICC_EVP_PKEY_CTX_new_id(ockCtx, ICC_EVP_PKEY_RSA, NULL);
    if (pctx == NULL) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA FAILURE ICC_EVP_PKEY_CTX_new_id");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_CTX_new_id() failed");
        goto cleanup;
    }

    ret = ICC_EVP_PKEY_keygen_init(ockCtx, pctx);
    if (ret != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA FAILURE ICC_EVP_PKEY_keygen_init");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_keygen_init() failed");
        goto cleanup;
    }

    snprintf(bitStr, sizeof(bitStr), "%d", (int)numBits);

#ifdef __MVS__
    forceToAscii(bitStr); // Ensure the value is ASCII before passing to OCK
#endif

#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
    ret = ICC_EVP_PKEY_CTX_ctrl_str(ockCtx, pctx, "rsa_keygen_bits", bitStr);
#ifdef __MVS__
#pragma convert(pop)
#endif
    if (ret <= 0) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSA FAILURE ICC_EVP_PKEY_CTX_ctrl_str (set bits)");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0,
                          "ICC_EVP_PKEY_CTX_ctrl_str() failed to set key size");
        goto cleanup;
    }

    snprintf(expStr, sizeof(expStr), "%ld", (long)e);

#ifdef __MVS__
    forceToAscii(expStr); // Ensure the value is ASCII before passing to OCK
#endif

#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
    ret = ICC_EVP_PKEY_CTX_ctrl_str(ockCtx, pctx, "rsa_keygen_pubexp", expStr);
#ifdef __MVS__
#pragma convert(pop)
#endif
    if (ret <= 0) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSA FAILURE ICC_EVP_PKEY_CTX_ctrl_str (set pubexp)");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(
            env, 0,
            "ICC_EVP_PKEY_CTX_ctrl_str() failed to set public exponent");
        goto cleanup;
    }

    ret = ICC_EVP_PKEY_keygen(ockCtx, pctx, &ockPKey);
    if (ret != ICC_OSSL_SUCCESS || ockPKey == NULL) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA FAILURE ICC_EVP_PKEY_keygen");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_keygen() failed");
        goto cleanup;
    }

    ockRSA = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
    if (ockRSA == NULL) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA FAILURE ICC_EVP_PKEY_get1_RSA");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_get1_RSA() failed");
        goto cleanup;
    }

    rsaKeyId = (jlong)((intptr_t)ockRSA);
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId %lx", rsaKeyId);
    }
#endif

cleanup:
    if (pctx != NULL) {
        ICC_EVP_PKEY_CTX_free(ockCtx, pctx);
        pctx = NULL;
    }

    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }

    if ((ockRSA != NULL) && (rsaKeyId == 0)) {
        ICC_RSA_free(ockCtx, ockRSA);
        ockRSA = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return rsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAKEY_createPrivateKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1createPrivateKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray privateKeyBytes) {
    static const char *functionName = "NativeInterface.RSAKEY_createPrivateKey";

    ICC_CTX             *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA             *ockRSA         = NULL;
    ICC_EVP_PKEY        *ockPKey        = NULL;
    unsigned char       *keyBytesNative = NULL;
    jboolean             isCopy         = 0;
    jlong                rsaKeyId       = 0;
    const unsigned char *pBytes         = NULL;
    jint                 size           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (privateKeyBytes == NULL) {
        throwOCKException(env, 0,
                          "The RSA Key Private Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return rsaKeyId;
    }
    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, privateKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE keyBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        if (debug) {
            gslogMessage("DETAIL_RSA KeyBytesNative allocated");
        }
        //  unsigned char * pBytes = (unsigned char *)keyBytesNative;
        pBytes = (const unsigned char *)keyBytesNative;
        //  jint size = (*env)->GetArrayLength(env, privateKeyBytes);
        size = (*env)->GetArrayLength(env, privateKeyBytes);
#ifdef DEBUG_RSA_DATA
        if (debug) {
            gslogMessagePrefix("DATA_RSA Private KeyBytes : ");
            gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
        }
#endif

        ockPKey = ICC_EVP_PKEY_new(ockCtx);
        if (NULL == ockPKey) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new ");
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
        } else {
            ICC_EVP_PKEY *ret =
                ICC_d2i_PrivateKey(ockCtx, 6, &ockPKey, &pBytes, (long)size);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA pointer to ICC_EVP_PKEY %x", ret);
            }
#endif
            if (ret == NULL) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE ICC_d2i_PrivateKey");
                }
#endif
                throwOCKException(env, 0, "ICC_d2i_PrivateKey failed");
            } else {
                ockRSA = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
                if (ockRSA == NULL) {
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_EVP_PKEY_get1_RSA");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_EVP_PKEY_get1_RSA failed");
                } else {
                    rsaKeyId = (jlong)((intptr_t)ockRSA);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_RSA  rsaKeyId %lx", rsaKeyId);
                    }
#endif
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

    return rsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAKEY_createPublicKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1createPublicKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray publicKeyBytes) {
    static const char *functionName = "NativeInterface.RSAKEY_createPublicKey";

    ICC_CTX             *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA             *ockRSA         = NULL;
    ICC_EVP_PKEY        *ockPKey        = NULL;
    unsigned char       *keyBytesNative = NULL;
    jboolean             isCopy         = 0;
    jlong                rsaKeyId       = 0;
    const unsigned char *pBytes         = NULL;
    jint                 size           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (publicKeyBytes == NULL) {
        throwOCKException(env, 0, "The RSA Key Public bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return rsaKeyId;
    }
    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, publicKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE keyBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA KeyBytesNative allocated");
        }
#endif
        pBytes = (const unsigned char *)keyBytesNative;
        size   = (*env)->GetArrayLength(env, publicKeyBytes);
#ifdef DEBUG_RSA_DATA
        if (debug) {
            gslogMessagePrefix("DATA_RSA PublicKeyBytes : ");
            gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
        }
#endif

        ockPKey = ICC_EVP_PKEY_new(ockCtx);
        if (NULL == ockPKey) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new");
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
        } else {
            ICC_EVP_PKEY *ret = ICC_d2i_PublicKey(ockCtx, ICC_EVP_PKEY_RSA,
                                                  &ockPKey, &pBytes, (int)size);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA ICC_EVP_PKEY  %x", ret);
            }
#endif
            if (ret == NULL) {
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE ICC_d2i_PublicKey");
                }
#endif
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_d2i_PublicKey failed");
            } else {
                ockRSA = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
                if (ockRSA == NULL) {
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_EVP_PKEY_get1_RSA");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_EVP_PKEY_get1_RSA failed");
                } else {
                    rsaKeyId = (jlong)((intptr_t)ockRSA);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_RSA rsaKeyId  %lx",
                                     (long)rsaKeyId);
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

    return rsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1getPrivateKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName =
        "NativeInterface.RSAKEY_getPrivateKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA         = (ICC_RSA *)((intptr_t)rsaKeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }

#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId  %lx", (long)rsaKeyId);
    }
#endif
    size = ICC_i2d_RSAPrivateKey(ockCtx, ockRSA, NULL);
    if (size <= 0) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE ICC_i2d_RSAPrivateKey");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_RSAPrivateKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE keyBytes");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE keyBytesNative ");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                unsigned char *pBytes = (unsigned char *)keyBytesNative;

                size = ICC_i2d_RSAPrivateKey(ockCtx, ockRSA, &pBytes);
                if (size <= 0) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_i2d_RSAPrivateKey");
                    }
#endif
                    throwOCKException(env, 0, "ICC_i2d_RSAPrivateKey failed");
                } else {
                    retKeyBytes = keyBytes;
#ifdef DEBUG_RSA_DATA
                    if (debug) {
                        gslogMessagePrefix("DATA_RSA private KeyBytes : ");
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

    return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName =
        "NativeInterface.RSAKEY_getPublicKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA         = (ICC_RSA *)((intptr_t)rsaKeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }
    size = ICC_i2d_RSAPublicKey(ockCtx, ockRSA, NULL);
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId %lx size %d ", (long)rsaKeyId,
                     (int)size);
    }
#endif
    if (size <= 0) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE ICC_i2d_RSAPublicKey");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_RSAPublicKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE keyBytes ");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE keyBytesNative ");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                unsigned char *pBytes = (unsigned char *)keyBytesNative;

                size = ICC_i2d_RSAPublicKey(ockCtx, ockRSA, &pBytes);
                if (size <= 0) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_i2d_RSAPublicKey");
                    }
#endif
                    throwOCKException(env, 0, "ICC_i2d_RSAPublicKey failed");
                } else {
                    retKeyBytes = keyBytes;
#ifdef DEBUG_RSA_DATA
                    if (debug) {
                        gslogMessagePrefix("DATA_RSA KeyBytes : ");
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
 * Method:    RSAKEY_createPKey
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1createPKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName = "NativeInterface.RSAKEY_createPKey";

    ICC_CTX      *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA      *ockRSA  = (ICC_RSA *)((intptr_t)rsaKeyId);
    ICC_EVP_PKEY *ockPKey = NULL;
    jlong         pkeyId  = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return pkeyId;
    }
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId %lx ", (long)rsaKeyId);
    }
#endif

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if (ockPKey == NULL) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
        int rc = ICC_EVP_PKEY_set1_RSA(ockCtx, ockPKey, ockRSA);
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA rc from ICC_EVP_PKEY_set1_RSA %d ", rc);
        }
#endif
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_set1_RSA %d",
                             rc);
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_set1_RSA failed");
        } else {
            pkeyId = (jlong)((intptr_t)ockPKey);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA pkeyId %lx=", pkeyId);
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
 * Method:    RSAKEY_size
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1size(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName = "NativeInterface.RSAKEY_size";

    ICC_CTX *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA *ockRSA = (ICC_RSA *)((intptr_t)rsaKeyId);
    int      size   = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return size;
    }
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId=%lx", (long)rsaKeyId);
    }
#endif

    size = ICC_RSA_size(ockCtx, ockRSA);
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA size=%d", size);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return size;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    RSAKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_RSAKEY_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName = "NativeInterface.RSAKEY_delete";

    ICC_CTX *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA *ockRSA = (ICC_RSA *)((intptr_t)rsaKeyId);

    if (debug) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId=%lx", (long)rsaKeyId);
    }
#endif
    if (ockRSA != NULL) {
        ICC_RSA_free(ockCtx, ockRSA);
        ockRSA = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
