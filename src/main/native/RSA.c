/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include "RSAPadding.h"
#include <stdint.h>

static int rsaPaddingMap(int rsaPaddingId);

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSACIPHER_public_encrypt
 * Signature: (JJI[BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSACIPHER_1public_1encrypt(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId,
    jint rsaPaddingId, jbyteArray plaintext, jint plaintextOff,
    jint plaintextLen, jbyteArray ciphertext, jint ciphertextOff) {
    static const char *functionName = "NativeInterface.RSA_public_encrypt";

    ICC_CTX       *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA           = (ICC_RSA *)((intptr_t)rsaKeyId);
    unsigned char *plaintextNative  = NULL;
    unsigned char *ciphertextNative = NULL;
    int            outLen           = 0;
    jboolean       isCopy;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_RSA_DETAIL
        gslogMessage(
            "DETAIL_RSACIPHER rsaKeyId %lx rsaPaddingId %x plaintextOff %d "
            "plaintextLen %d ciphertextOff %d",
            (long)rsaKeyId, rsaPaddingId, (int)plaintextOff, (int)plaintextLen,
            (int)ciphertextOff);
#endif
    }

    if ((ockRSA == NULL) || (plaintext == NULL) || (ciphertext == NULL) ||
        (plaintextOff < 0) || (plaintextOff > plaintextLen) ||
        (ciphertextOff < 0)) {
        throwOCKException(env, 0, "The RSA input parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return outLen;
    }
    plaintextNative  = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    if (NULL == plaintextNative || NULL == ciphertextNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE plaintextNative or cihertextNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER Data to encrypt - %d bytes: ",
                               (int)plaintextLen);
            gslogMessageHex((char *)plaintextNative, 0, (int)plaintextLen, 0, 0,
                            NULL);
        }
#endif
        outLen = ICC_RSA_public_encrypt(ockCtx, (int)plaintextLen,
                                        plaintextNative + (int)plaintextOff,
                                        ciphertextNative + (int)ciphertextOff,
                                        ockRSA, rsaPaddingMap(rsaPaddingId));
        if (outLen == ICC_OSSL_FAILURE || outLen == ICC_FAILURE) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_RSACIPHER FAILURE ICC_RSA_public_encrypt ");
            }
#endif
            throwOCKException(env, 0, "ICC_RSA_public_encrypt failed");
        }

#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER Encrypted data - %d bytes: ",
                               outLen);
            gslogMessageHex((char *)ciphertextNative + (int)ciphertextOff, 0,
                            outLen, 0, 0, NULL);
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

    if (debug) {
#ifdef DEBUG_CIPHER_DETAIL
        gslogMessage("DETAIL_RSACIPHER outLen %d", outLen);
#endif
        gslogFunctionExit(functionName);
    }

    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSACIPHER_private_encrypt
 * Signature: (JJI[BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSACIPHER_1private_1encrypt(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId,
    jint rsaPaddingId, jbyteArray plaintext, jint plaintextOff,
    jint plaintextLen, jbyteArray ciphertext, jint ciphertextOff,
    jboolean convertKey) {
    static const char *functionName = "NativeInterface.RSA_private_encrypt";

    ICC_CTX       *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA           = (ICC_RSA *)((intptr_t)rsaKeyId);
    unsigned char *plaintextNative  = NULL;
    unsigned char *ciphertextNative = NULL;
    int            outLen           = 0;
    jboolean       isCopy;

    if ((ockRSA == NULL) || (plaintext == NULL) || (ciphertext == NULL) ||
        (plaintextOff < 0) || (plaintextOff > plaintextLen) ||
        (ciphertextOff < 0)) {
        throwOCKException(env, 0, "The RSA input parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return outLen;
    }
    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_RSA_DETAIL
        gslogMessage(
            "DETAIL_RSACIPHER rsaKeyId %lx rsaPaddingId %x plaintextOff %d "
            "plaintextLen %d ciphertextOff %d",
            (long)rsaKeyId, rsaPaddingId, (int)plaintextOff, (int)plaintextLen,
            (int)ciphertextOff);
#endif
    }

    plaintextNative  = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    if (NULL == plaintextNative || NULL == ciphertextNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE plaintextNative or cihertextNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER  Data to encrypt - %d bytes: ",
                               (int)plaintextLen);
            gslogMessageHex((char *)plaintextNative, 0, (int)plaintextLen, 0, 0,
                            NULL);
        }
#endif
        if (convertKey) {
            // Only done for Plain RSA keys
            ICC_RSA_FixEncodingZeros(ockCtx, ockRSA, NULL, 0);
        }

        outLen = ICC_RSA_private_encrypt(ockCtx, (int)plaintextLen,
                                         plaintextNative + (int)plaintextOff,
                                         ciphertextNative + (int)ciphertextOff,
                                         ockRSA, rsaPaddingMap(rsaPaddingId));
        if (outLen == ICC_OSSL_FAILURE || outLen == ICC_FAILURE) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_RSACIPHER FAILURE ICC_RSA_private_encrypt ");
            }
#endif
            throwOCKException(env, 0, "ICC_RSA_private_encrypt failed");
        }

#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER Encrypted data - %d bytes: ",
                               outLen);
            gslogMessageHex((char *)ciphertextNative + (int)ciphertextOff, 0,
                            outLen, 0, 0, NULL);
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

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSACIPHER_public_decrypt
 * Signature: (JJI[BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSACIPHER_1public_1decrypt(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId,
    jint rsaPaddingId, jbyteArray ciphertext, jint ciphertextOff,
    jint ciphertextLen, jbyteArray plaintext, jint plaintextOff) {
    static const char *functionName = "NativeInterface.RSA_public_decrypt";

    ICC_CTX       *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA           = (ICC_RSA *)((intptr_t)rsaKeyId);
    unsigned char *plaintextNative  = NULL;
    unsigned char *ciphertextNative = NULL;
    int            outLen           = 0;
    jboolean       isCopy;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_RSA_DETAIL
        gslogMessage(
            "DETAIL_RSACIPHER rsaKeyId %lx rsaPaddingId %x plaintextOff %d "
            "ciphertextLen %d ciphertextOff %d",
            (long)rsaKeyId, rsaPaddingId, (int)plaintextOff, (int)ciphertextLen,
            (int)ciphertextOff);
#endif
    }
    if ((ockRSA == NULL) || (plaintext == NULL) || (ciphertext == NULL) ||
        (ciphertextOff < 0) || (ciphertextOff > ciphertextLen) ||
        (plaintextOff < 0)) {
        throwOCKException(env, 0, "The RSA input arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return outLen;
    }
    plaintextNative  = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    if (NULL == plaintextNative || NULL == ciphertextNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE plaintextNative or cihertextNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER Data to decrypt - %d bytes: ",
                               (int)ciphertextLen);
            gslogMessageHex((char *)ciphertextNative, 0, (int)ciphertextLen, 0,
                            0, NULL);
        }
#endif

        outLen = ICC_RSA_public_decrypt(ockCtx, (int)ciphertextLen,
                                        ciphertextNative + (int)ciphertextOff,
                                        plaintextNative + (int)plaintextOff,
                                        ockRSA, rsaPaddingMap(rsaPaddingId));
        if (outLen == ICC_OSSL_FAILURE || outLen == ICC_FAILURE) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_RSACIPHER FAILURE ICC_RSA_public_decrypt ");
            }
#endif
            throwOCKException(env, 0, "ICC_RSA_public_decrypt failed");
        }

#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER Decrypted data - %d bytes: ",
                               outLen);
            gslogMessageHex((char *)plaintextNative, 0, outLen, 0, 0, NULL);
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

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSACIPHER_private_decrypt
 * Signature: (JJI[BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSACIPHER_1private_1decrypt(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId,
    jint rsaPaddingId, jbyteArray ciphertext, jint ciphertextOff,
    jint ciphertextLen, jbyteArray plaintext, jint plaintextOff,
    jboolean convertKey) {
    static const char *functionName = "NativeInterface.RSA_private_decrypt";

    ICC_CTX       *ockCtx           = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA           = (ICC_RSA *)((intptr_t)rsaKeyId);
    unsigned char *plaintextNative  = NULL;
    unsigned char *ciphertextNative = NULL;
    int            outLen           = 0;
    jboolean       isCopy;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_RSA_DETAIL
        gslogMessage(
            "DETAIL_RSACIPHER rsaKeyId %lx rsaPaddingId %x ciphertextOff %d "
            "ciphertextLen %d plaintextOff %d",
            (long)rsaKeyId, rsaPaddingId, (int)ciphertextOff,
            (int)ciphertextLen, plaintextOff);
#endif
    }
    if ((ockRSA == NULL) || (plaintext == NULL) || (ciphertext == NULL) ||
        (ciphertextOff < 0) || (ciphertextOff > ciphertextLen) ||
        (plaintextOff < 0)) {
        throwOCKException(env, 0, "The RSA input arguments are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return outLen;
    }
    plaintextNative  = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    if (NULL == plaintextNative || NULL == ciphertextNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE plaintextNative or cihertextNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");
    } else {
#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER Data to decrypt - %d bytes: ",
                               (int)ciphertextLen);
            gslogMessageHex((char *)ciphertextNative, 0, (int)ciphertextLen, 0,
                            0, NULL);
        }
#endif
        if (convertKey) {
            // Only done for Plain RSA keys
            ICC_RSA_FixEncodingZeros(ockCtx, ockRSA, NULL, 0);
        }

        outLen = ICC_RSA_private_decrypt(ockCtx, (int)ciphertextLen,
                                         ciphertextNative + (int)ciphertextOff,
                                         plaintextNative + (int)plaintextOff,
                                         ockRSA, rsaPaddingMap(rsaPaddingId));
        if (outLen == ICC_OSSL_FAILURE || outLen == ICC_FAILURE) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage(
                    "DETAIL_RSACIPHER FAILURE ICC_RSA_private_decrypt ");
            }
#endif
            throwOCKException(env, 0, "ICC_private_decrypt failed");
        }
#ifdef DEBUG_CIPHER_DETAIL
        if (debug) {
            gslogMessagePrefix("DETAIL_RSACIPHER Decrypted data - %d bytes: ",
                               outLen);
            gslogMessageHex((char *)plaintextNative, 0, outLen, 0, 0, NULL);
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

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return outLen;
}

static int rsaPaddingMap(int rsaPaddingId) {
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSACIPHER rsaPaddingId %lx ", (long)rsaPaddingId);
    }
#endif

    switch (rsaPaddingId) {
        case RSAPAD_NONE:
            return ICC_RSA_NO_PADDING;
        case RSAPAD_PKCS1:
            return ICC_RSA_PKCS1_PADDING;
        case RSAPAD_OAEP:
            return ICC_RSA_PKCS1_OAEP_PADDING;
        default:
            return -1;
    }
}
