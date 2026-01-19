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
#include "Padding.h"
#include "Utils.h"
#include "ExceptionCodes.h"
#include <stdint.h>

typedef struct OCKCipher {
    const ICC_EVP_CIPHER *cipher;
    ICC_EVP_CIPHER_CTX   *cipherCtx;
} OCKCipher;

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_create
 * Signature: (JLjava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1create(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jstring cipherName) {
    static const char *functionName = "NativeInterface.POLY1305CIPHER_create";

    ICC_CTX    *ockCtx          = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher  *ockCipher       = NULL;
    const char *cipherNameChars = NULL;
    jlong       retCipher       = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (cipherName == NULL) {
        throwOCKException(env, 0, "The specified Cipher name is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retCipher;
    }
    ockCipher = (OCKCipher *)malloc(sizeof(OCKCipher));
    if (ockCipher == NULL) {
        throwOCKException(env, 0, "Error allocating OCKCipher");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return 0;
    } else {
        ockCipher->cipher    = NULL;
        ockCipher->cipherCtx = NULL;
    }

    if (!(cipherNameChars = (*env)->GetStringUTFChars(env, cipherName, NULL))) {
        throwOCKException(env, 0, "GetStringUTFChars() failed");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        FREE_N_NULL(ockCipher);
        return 0;
    }

    if (debug) {
        gslogMessage("cipher=%s", cipherNameChars);
    }

    ockCipher->cipher = ICC_EVP_get_cipherbyname(ockCtx, cipherNameChars);
    if (NULL == ockCipher->cipher) {
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_get_cipherbyname() failed");
    } else {
        ockCipher->cipherCtx = ICC_EVP_CIPHER_CTX_new(ockCtx);
        if (NULL == ockCipher->cipherCtx) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_CIPHER_CTX_new failed");
        } else {
            ICC_EVP_CIPHER_CTX_init(ockCtx, ockCipher->cipherCtx);

            retCipher = (jlong)((intptr_t)ockCipher);
        }
    }

    (*env)->ReleaseStringUTFChars(env, cipherName, cipherNameChars);

    // If an error occurred, free up the OCKCipher allocation
    //
    if (retCipher == 0) {
        FREE_N_NULL(ockCipher);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retCipher;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_init
 * Signature: (JJZ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1init(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId,
    jint isEncrypt, jbyteArray key, jbyteArray iv) {
    static const char *functionName = "NativeInterface.POLY1305CIPHER_init";

    ICC_CTX       *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher     *ockCipher = (OCKCipher *)((intptr_t)ockCipherId);
    unsigned char *keyNative = NULL;
    unsigned char *ivNative  = NULL;
    int            rc        = ICC_OSSL_SUCCESS;
    jboolean       isCopy    = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockCipher == NULL) || (key == NULL)) {
        throwOCKException(
            env, 0, "The specified Poly1305Cipher arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
    /* Convert the key and iv to c array*/
    // iv can be null for ECB
    if (NULL != iv) {
        ivNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, iv, &isCopy));
    }
    keyNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));

    if (NULL == keyNative) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        rc = isEncrypt
                 ? ICC_EVP_EncryptInit(ockCtx, ockCipher->cipherCtx,
                                       ockCipher->cipher, keyNative, ivNative)
                 : ICC_EVP_DecryptInit(ockCtx, ockCipher->cipherCtx,
                                       ockCipher->cipher, keyNative, ivNative);
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_Encrypt/DecryptInit failed");
        }
    }

    if (keyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_clean
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1clean(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId) {
    static const char *functionName = "NativeInterface.POLY1305CIPHER_clean";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher *ockCipher = (OCKCipher *)((intptr_t)ockCipherId);
    int        rc        = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockCipher == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
    if ((ockCipher->cipherCtx) != NULL) {
        rc = ICC_EVP_CIPHER_CTX_cleanup(ockCtx, ockCipher->cipherCtx);
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_CIPHER_CTX_cleanup failed");
        }
    }
    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_setPadding
 * Signature: (JJZ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1setPadding(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId,
    jint paddingId) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_setPadding";

    ICC_CTX   *ockCtx     = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher *ockCipher  = (OCKCipher *)((intptr_t)ockCipherId);
    int        rc         = ICC_OSSL_SUCCESS;
    int        ockPadType = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockCipher == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        throwOCKException(
            env, 0, "The specified Poly1305Cipher identifier is incorrect.");
        return;
    } else if (ockCipher->cipherCtx == NULL) {
        if (debug) {
            gslogFunctionExit(functionName);
        }
        throwOCKException(env, 0, "The cipher context is incorrect.");
        return;
    }
    switch (paddingId) {
        case PADDING_NONE:
            ockPadType = 0;
            break;

        case PADDING_PKCS5:
            ockPadType = 1;
            break;

        default:
            throwOCKException(env, 0, "Invalid padding type");
            rc = ICC_OSSL_FAILURE;
    }

    if (rc == ICC_OSSL_SUCCESS) {
        rc = ICC_EVP_CIPHER_CTX_set_padding(ockCtx, ockCipher->cipherCtx,
                                            ockPadType);
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_set_padding failed");
        }
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_getBlockSize
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1getBlockSize(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_getBlockSize";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher *ockCipher = (OCKCipher *)((intptr_t)ockCipherId);
    int        blockSize = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
        blockSize = ICC_EVP_CIPHER_block_size(ockCtx, ockCipher->cipher);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return blockSize;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_getKeyLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1getKeyLength(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_getKeyLength";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher *ockCipher = (OCKCipher *)((intptr_t)ockCipherId);
    int        keyLength = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
        keyLength = ICC_EVP_CIPHER_key_length(ockCtx, ockCipher->cipher);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return keyLength;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_getIVLength
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1getIVLength(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_getIVLength";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher *ockCipher = (OCKCipher *)((intptr_t)ockCipherId);
    int        ivLength  = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
        ivLength = ICC_EVP_CIPHER_iv_length(ockCtx, ockCipher->cipher);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return ivLength;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_getOID
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1getOID(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId) {
    static const char *functionName = "NativeInterface.POLY1305CIPHER_getOID";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher *ockCipher = (OCKCipher *)((intptr_t)ockCipherId);
    int        oid       = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockCipher != NULL) && (ockCipher->cipher != NULL)) {
        oid = ICC_EVP_CIPHER_type(ockCtx, ockCipher->cipher);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return oid;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_encryptUpdate
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1encryptUpdate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId,
    jbyteArray plaintext, jint plaintextOffset, jint plaintextLen,
    jbyteArray ciphertext, jint ciphertextOffset) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_encryptUpdate";

    ICC_CTX       *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher     *ockCipher        = (OCKCipher *)((intptr_t)ockCipherId);
    unsigned char *plaintextNative  = NULL;
    unsigned char *ciphertextNative = NULL;
    int            outLen           = 0;
    int            rc               = ICC_OSSL_SUCCESS;
    jboolean       isCopy           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockCipher == NULL) || (plaintext == NULL)) {
        throwOCKException(env, 0,
                          "The specified Poly1305Cipher encrypt update "
                          "arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jint)outLen;
    }
    /* Convert the jbytearray plaintext and ciphertext to c array*/
    plaintextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));

    // Cipher text output is null for AAD update
    if (NULL != ciphertext) {
        ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, ciphertext, &isCopy));
    }

    if (NULL == plaintextNative) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("PlainText : ");
            gslogMessageHex((char *)plaintextNative, plaintextOffset,
                            plaintextLen, 0, 0, NULL);
        }
#endif

        if (NULL != ciphertextNative) {
            // Update cipher text...
            rc = ICC_EVP_EncryptUpdate(
                ockCtx, ockCipher->cipherCtx,
                ciphertextNative + ciphertextOffset, &outLen,
                plaintextNative + plaintextOffset, (int)plaintextLen);
        } else {
            // Update AAD...
            rc = ICC_EVP_EncryptUpdate(
                ockCtx, ockCipher->cipherCtx, NULL, &outLen,
                plaintextNative + plaintextOffset, (int)plaintextLen);
        }

        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_EncryptUpdate failed!\n");
        } else {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                if (NULL != ciphertextNative) {
                    gslogMessagePrefix("CipherText : ");
                    gslogMessageHex((char *)ciphertextNative, ciphertextOffset,
                                    outLen, 0, 0, NULL);
                } else {
                    gslogMessagePrefix("AAD : ");
                    gslogMessageHex((char *)plaintextNative, plaintextOffset,
                                    outLen, 0, 0, NULL);
                }
            }
#endif
        }
    }

    if (plaintextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative,
                                              0);
    }

    if (ciphertextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative,
                                              0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jint)outLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_encryptFinal
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1encryptFinal(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId,
    jbyteArray plaintext, jint plaintextOffset, jint plaintextLen,
    jbyteArray ciphertext, jint ciphertextOffset, jbyteArray tag) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_encryptFinal";

    ICC_CTX         *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher       *ockCipher        = (OCKCipher *)((intptr_t)ockCipherId);
    unsigned char   *plaintextNative  = NULL;
    unsigned char   *ciphertextNative = NULL;
    unsigned char   *tagNative        = NULL;
    static const int EVP_CTRL_AEAD_GET_TAG = 0x10;
    static const int POLY1305_TAG_SIZE     = 16;
    int              updateOutlen          = 0;
    int              finalOutlen           = 0;
    int              rc                    = ICC_OSSL_SUCCESS;
    jboolean         isCopy                = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockCipher == NULL) || (ciphertext == NULL)) {
        throwOCKException(env, 0,
                          "The specified Poly1305Cipher encrypt final "
                          "arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jint)finalOutlen;
    }
    /* Convert the jbytearray plaintext and ciphertext to c array*/
    if (plaintextLen > 0) {
        plaintextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, plaintext, &isCopy));
    }
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));

    tagNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, tag, &isCopy));

    if ((NULL == ciphertextNative) ||
        ((plaintextLen > 0) && (plaintextNative == NULL)) ||
        (NULL == tagNative)) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        if (plaintextLen > 0) {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                gslogMessagePrefix("PlainText : ");
                gslogMessageHex((char *)plaintextNative, plaintextOffset,
                                plaintextLen, 0, 0, NULL);
            }
#endif

            rc = ICC_EVP_EncryptUpdate(
                ockCtx, ockCipher->cipherCtx,
                ciphertextNative + ciphertextOffset, &updateOutlen,
                plaintextNative + plaintextOffset, (int)plaintextLen);
            if (rc != ICC_OSSL_SUCCESS) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_EVP_EncryptUpdate failed!\n");
            } else {
#ifdef DEBUG_CIPHER_DATA
                if (debug) {
                    gslogMessagePrefix("CipherText [update] : ");
                    gslogMessageHex((char *)ciphertextNative, ciphertextOffset,
                                    updateOutlen, 0, 0, NULL);
                }
#endif
            }
        }

        if (rc == ICC_OSSL_SUCCESS) {
            rc = ICC_EVP_EncryptFinal(
                ockCtx, ockCipher->cipherCtx,
                ciphertextNative + ciphertextOffset + updateOutlen,
                &finalOutlen);
            if (rc != ICC_OSSL_SUCCESS) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_EVP_EncryptFinal failed!\n");
            } else {
#ifdef DEBUG_CIPHER_DATA
                if (debug) {
                    gslogMessagePrefix("CipherText [final] : ");
                    gslogMessageHex((char *)ciphertextNative,
                                    ciphertextOffset + updateOutlen,
                                    finalOutlen, 0, 0, NULL);

                    gslogMessagePrefix("CipherText : ");
                    gslogMessageHex((char *)ciphertextNative, ciphertextOffset,
                                    updateOutlen + finalOutlen, 0, 0, NULL);
                }
#endif
            }
        }
    }

    rc = ICC_EVP_CIPHER_CTX_ctrl(ockCtx, ockCipher->cipherCtx,
                                 EVP_CTRL_AEAD_GET_TAG, POLY1305_TAG_SIZE,
                                 tagNative);

    if (rc != ICC_OSSL_SUCCESS) {
        ockCheckStatus(ockCtx);
        throwOCKException(
            env, 0, "ICC_EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_GET_TAG) failed!\n");
    } else {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("Cipher Tag : ");
            gslogMessageHex((char *)tagNative, 0, POLY1305_TAG_SIZE, 0, 0,
                            NULL);
        }
#endif
    }

    if (plaintextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative,
                                              0);
    }

    if (ciphertextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative,
                                              0);
    }

    if (tagNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, tag, tagNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jint)(updateOutlen + finalOutlen);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_decryptUpdate
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1decryptUpdate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId,
    jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen,
    jbyteArray plaintext, jint plaintextOffset) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_decryptUpdate";

    ICC_CTX       *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher     *ockCipher        = (OCKCipher *)((intptr_t)ockCipherId);
    unsigned char *plaintextNative  = NULL;
    unsigned char *ciphertextNative = NULL;
    int            outLen           = 0;
    int            rc               = ICC_OSSL_SUCCESS;
    jboolean       isCopy           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if ((ockCipher == NULL) || (ciphertext == NULL)) {
        throwOCKException(env, 0,
                          "The specified Poly1305Cipher decrypt update "
                          "arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jint)outLen;
    }
    /* Convert the jbytearray plaintext and ciphertext to c array*/
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));

    // Plain text output is null for AAD update
    if (NULL != plaintext) {
        plaintextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, plaintext, &isCopy));
    }

    if (NULL == ciphertextNative) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
#ifdef DEBUG_CIPHER_DATA
        if (debug) {
            gslogMessagePrefix("CipherText : ");
            gslogMessageHex((char *)ciphertextNative, ciphertextOffset,
                            ciphertextLen, 0, 0, NULL);
        }
#endif

        if (NULL != plaintextNative) {
            // Update plain text...
            rc = ICC_EVP_DecryptUpdate(
                ockCtx, ockCipher->cipherCtx, plaintextNative + plaintextOffset,
                &outLen, ciphertextNative + ciphertextOffset,
                (int)ciphertextLen);
        } else {
            // Update AAD...
            rc = ICC_EVP_DecryptUpdate(
                ockCtx, ockCipher->cipherCtx, NULL, &outLen,
                ciphertextNative + ciphertextOffset, (int)ciphertextLen);
        }

        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_DecryptUpdate failed!\n");
        } else {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                gslogMessagePrefix("PlainText : ");
                if (NULL != plaintextNative) {
                    gslogMessageHex((char *)plaintextNative, plaintextOffset,
                                    outLen, 0, 0, NULL);
                }
            }
#endif
        }
    }

    if (ciphertextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative,
                                              0);
    }

    if (plaintextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative,
                                              0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jint)outLen;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_decryptFinal
 * Signature: (JJI[B[B)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1decryptFinal(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId,
    jbyteArray ciphertext, jint ciphertextOffset, jint ciphertextLen,
    jbyteArray plaintext, jint plaintextOffset, jbyteArray tag) {
    static const char *functionName =
        "NativeInterface.POLY1305CIPHER_decryptFinal";

    ICC_CTX         *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher       *ockCipher        = (OCKCipher *)((intptr_t)ockCipherId);
    unsigned char   *plaintextNative  = NULL;
    unsigned char   *ciphertextNative = NULL;
    unsigned char   *tagNative        = NULL;
    static const int EVP_CTRL_AEAD_SET_TAG = 0x11;
    static const int POLY1305_TAG_SIZE     = 16;
    int              updateOutlen          = 0;
    int              finalOutlen           = 0;
    int              rc                    = ICC_OSSL_SUCCESS;
    jboolean         isCopy                = 0;
    unsigned long    errCode               = 0;
    const char      *errStr                = NULL;
    int              exceptionCode         = 0;
    const char      *exceptionMsg          = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if ((ockCipher == NULL) || (plaintext == NULL)) {
        throwOCKException(env, 0,
                          "The specified Poly1305Cipher decrypt final "
                          "arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jint)finalOutlen;
    }
    /* Convert the jbytearray plaintext and ciphertext to c array*/
    if (ciphertextLen > 0) {
        ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
            env, ciphertext, &isCopy));
    }
    plaintextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));

    tagNative =
        (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, tag, &isCopy));

    if ((NULL == plaintextNative) ||
        ((ciphertextLen > 0) && (ciphertextNative == NULL)) ||
        (NULL == tagNative)) {
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        if (ciphertextLen > 0) {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                gslogMessagePrefix("CipherText : ");
                gslogMessageHex((char *)ciphertextNative, ciphertextOffset,
                                ciphertextLen, 0, 0, NULL);
            }
#endif

            rc = ICC_EVP_DecryptUpdate(
                ockCtx, ockCipher->cipherCtx, plaintextNative + plaintextOffset,
                &updateOutlen, ciphertextNative + ciphertextOffset,
                (int)ciphertextLen);

            if (rc != ICC_OSSL_SUCCESS) {
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_EVP_DecryptUpdate failed!\n");
            } else {
#ifdef DEBUG_CIPHER_DATA
                if (debug) {
                    gslogMessagePrefix("PlainText [update] : ");
                    gslogMessageHex((char *)plaintextNative, plaintextOffset,
                                    updateOutlen, 0, 0, NULL);
                }
#endif
            }
        }

        rc = ICC_EVP_CIPHER_CTX_ctrl(ockCtx, ockCipher->cipherCtx,
                                     EVP_CTRL_AEAD_SET_TAG, POLY1305_TAG_SIZE,
                                     tagNative);

        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(
                env, 0,
                "ICC_EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_SET_TAG) failed!\n");
        } else {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                gslogMessagePrefix("Cipher Tag : ");
                gslogMessageHex((char *)tagNative, 0, POLY1305_TAG_SIZE, 0, 0,
                                NULL);
            }
#endif
        }

        if (rc == ICC_OSSL_SUCCESS) {
#ifdef DEBUG_CIPHER_DATA
            if (debug) {
                gslogMessage("plaintextOffset: %i", plaintextOffset);
                gslogMessage("updateOutlen:    %i", updateOutlen);
                gslogMessage("finalOutlen:     %i", finalOutlen);
            }
#endif

            rc = ICC_EVP_DecryptFinal(
                ockCtx, ockCipher->cipherCtx,
                plaintextNative + plaintextOffset + updateOutlen, &finalOutlen);

            if (rc != ICC_OSSL_SUCCESS) {
#ifdef DEBUG_CIPHER_DATA
                if (debug) {
                    gslogMessage("ICC_EVP_DecryptFinal(): rc: %i", rc);
                }
#endif

                errCode      = ICC_ERR_peek_last_error(ockCtx);
                errStr       = ICC_ERR_reason_error_string(ockCtx, errCode);
                exceptionMsg = "ICC_EVP_DecryptFinal failed!\n";

#ifdef DEBUG_CIPHER_DATA
                if (debug) {
                    gslogMessage("errCode:      %ul", errCode);
                    gslogMessage("errStr:       %s", errStr);
                    gslogMessage("exceptionMsg: %s", exceptionMsg);
                }
#endif

                if (errStr == NULL) {
                    exceptionCode = GKR_UNSPECIFIED;
                }

                ockCheckStatus(ockCtx);
                throwOCKException(env, exceptionCode, exceptionMsg);
            } else {
#ifdef DEBUG_CIPHER_DATA
                if (debug) {
                    gslogMessage("finalOutlen:     %i", finalOutlen);

                    gslogMessagePrefix("PlainText [final] : ");
                    gslogMessageHex((char *)plaintextNative,
                                    plaintextOffset + updateOutlen, finalOutlen,
                                    0, 0, NULL);

                    gslogMessagePrefix("PlainText : ");
                    gslogMessageHex((char *)plaintextNative, plaintextOffset,
                                    updateOutlen + finalOutlen, 0, 0, NULL);
                }
#endif
            }
        }
    }

    if (ciphertextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative,
                                              0);
    }

    if (plaintextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative,
                                              0);
    }

    if (tagNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, tag, tagNative, 0);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jint)(updateOutlen + finalOutlen);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_base_NativeInterface
 * Method:    POLY1305CIPHER_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_base_NativeInterface_POLY1305CIPHER_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong ockCipherId) {
    static const char *functionName = "NativeInterface.POLY1305CIPHER_delete";

    ICC_CTX   *ockCtx    = (ICC_CTX *)((intptr_t)ockContextId);
    OCKCipher *ockCipher = (OCKCipher *)((intptr_t)ockCipherId);
    int        rc        = ICC_OSSL_SUCCESS;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (ockCipher == NULL) {
        // Nothing to do
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return;
    }
    if (ockCipher->cipherCtx != NULL) {
        rc = ICC_EVP_CIPHER_CTX_free(ockCtx, ockCipher->cipherCtx);
        ockCipher->cipherCtx = NULL;
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
            throwOCKException(env, 0, "ICC_EVP_CIPHER_CTX_free failed!\n");
        } else {
            FREE_N_NULL(ockCipher);
        }
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
