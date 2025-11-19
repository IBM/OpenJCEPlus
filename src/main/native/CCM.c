/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>
#include <iccglobals.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Padding.h"
#include "Utils.h"
#include "zHardwareFunctions.h"

#define ICC_AES_CCM_CRYPTFINAL_FAILED 4
#define GetPRIMITICEARRAYCRITICAL 5
#define ICC_AES_CCM_TAG_MISMATCH 6

#ifdef WINDOWS
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

// Pointers of functions that are only available on some hardware (might be
// null)
ECB_FuncPtr   CCMECB;    // equivalent to s390_km_native
GHASH_FuncPtr CCMGHASH;  // equivalent to s390_kimd_native
zS390_FuncPtr CCMzS390;  // equivalent to s390_kmccm_native

char* getVersion_CCM(void) {
    ICC_STATUS status;
    ICC_CTX*   ctx    = NULL;
    void*      buffer = NULL;

    ctx    = ICC_Init(&status, NULL);
    buffer = calloc(10, 1);
    ICC_GetValue(ctx, &status, ICC_VERSION, buffer, 10);
    return buffer;
}

char getCharFromLong_CCM(unsigned long nb, int power) {
    char* ptr;
    nb  = nb >> power;
    ptr = ((char*)&nb) + sizeof(long) - 1;  // get last byte
    return *ptr;
}

void putLongtoByteArray_CCM(long number, char* bArray, int startIndex) {
    bArray[startIndex]     = getCharFromLong_CCM(number, 56);
    bArray[startIndex + 1] = getCharFromLong_CCM(number, 48);
    bArray[startIndex + 2] = getCharFromLong_CCM(number, 40);
    bArray[startIndex + 3] = getCharFromLong_CCM(number, 32);
    bArray[startIndex + 4] = getCharFromLong_CCM(number, 24);
    bArray[startIndex + 5] = getCharFromLong_CCM(number, 16);
    bArray[startIndex + 6] = getCharFromLong_CCM(number, 8);
    bArray[startIndex + 7] = getCharFromLong_CCM(number, 0);
}

void printByteArray_CCM(char* name, unsigned char* input, int len) {
    int i = 0;
    printf("%s: [", name);
    for (i = 0; i < len; i++) {
        if (i > 0) {
            printf(":");
        }
        printf("%02x", input[i]);
    }
    printf("]\n");
}

void z_km_native_CCM(signed char* in, int inputLength, int inputOffset,
                     signed char* out, int outputOffset,
                     signed char* parm_block, long mode) {
    UDATA len   = inputLength;
    UDATA _mode = mode;
    CCMECB(in + inputOffset, out + outputOffset, &len, parm_block, &_mode);
}

void z_kimd_native_CCM(signed char* in, int inputLength, int inputOffset,
                       signed char* parm_block, long mode) {
    UDATA _mode = mode;
    UDATA len   = inputLength;
    CCMGHASH(in + inputOffset, &len, parm_block, &_mode);
}

void handleIV_CCM(int ivLength, int keyLen, int blockSize, int J0Offset,
                  char* iv, char* key, char* addedParams) {
#if defined(S390_PLATFORM) || defined(__MVS__)
    // Computing hash-key
    int   offset             = 0;
    int   fc                 = 0;
    int   i                  = 0;
    int   lenn               = 0;
    int   lastIVLen          = blockSize;
    int   ivLengthOG         = ivLength;
    char* ghashParamBlockPtr = NULL;

    if (ivLength == 12) {
        addedParams[J0Offset + blockSize - 1] = 1;
        memcpy(addedParams + J0Offset, iv, ivLength);
    } else {
        char hashSubkey[blockSize];
        char zeros[blockSize];
        char hashSubkeyParamBlock[keyLen];
        char ghashParamBlock[2 * blockSize];

        fc = (keyLen == 16) ? 18 : (keyLen == 24) ? 19 : 20;

        memset(&hashSubkey, 0, blockSize);
        memset(&zeros, 0, blockSize);
        memcpy(&hashSubkeyParamBlock, key, keyLen);
        z_km_native_CCM((signed char*)&zeros, blockSize, 0,
                        (signed char*)&hashSubkey, 0,
                        (signed char*)&hashSubkeyParamBlock, fc);

        // Computing GHash for IV
        ghashParamBlockPtr = (char*)&ghashParamBlock;
        memset(&ghashParamBlock, 0, blockSize);
        memcpy(ghashParamBlockPtr + blockSize, &hashSubkey, blockSize);

        if (ivLength >= blockSize) {
            lenn = ivLength - (ivLength % blockSize);
            z_kimd_native_CCM((signed char*)iv, lenn, offset,
                              (signed char*)&ghashParamBlock, 65);
            ivLength -= lenn;
            offset += lenn;
        }

        if (ivLength > 0) {
            lastIVLen *= 2;
        }
        char lastIV[lastIVLen];
        memset(&lastIV, 0, lastIVLen);
        if (ivLength > 0) {
            memcpy(&lastIV, iv + offset, ivLength);
        }

        // Appending IV.length
        putLongtoByteArray_CCM(ivLengthOG * 8, (char*)&lastIV, lastIVLen - 8);
        z_kimd_native_CCM((signed char*)&lastIV, lastIVLen, 0,
                          (signed char*)&ghashParamBlock, 65);

        // Updating addedParam
        for (i = 0; i < blockSize; i++) {
            addedParams[J0Offset + i] = ghashParamBlock[i];
        }
    }
#endif
}

int checkTagMismatch_CCM(char* input, int inputLen, char* parm_block,
                         int tagOffset, int tagLen) {
#if defined(S390_PLATFORM) || defined(__MVS__)
    // check entire authentication tag for time-consistency

    int i        = 0;
    int mismatch = 0;
#if 0
    char tag[tagLen];
    char newTag[tagLen];

    memcpy(&tag, input + inputLen, tagLen);
    memcpy(&newTag, parm_block + tagOffset, tagLen);
#else
    char* tag    = input + inputLen;
    char* newTag = parm_block + tagOffset;
#endif
    for (i = 0; i < tagLen; i++) {
        mismatch |= tag[i] ^ newTag[i];
    }

    return (mismatch == 0) ? 0 : -1;
#else
    return 0;
#endif
}

/*============================================================================
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    internal functions
 * Signature:
 */
int CCM_decrypt_core(JNIEnv* env, ICC_CTX* ockCtx, unsigned char* key,
                     int keyLen, unsigned char* iv, int ivLen,
                     unsigned char* ciphertext, unsigned long ciphertextLen,
                     unsigned char* plaintext, unsigned long plaintextLen,
                     unsigned char* aad, int aadLen, int tagLen) {
    int                rc           = ICC_OSSL_SUCCESS;
    static const char* functionName = "NativeInterface.CCM_decrypt_core";

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    // obtain up to last block of plaintext and provide tag to compare
    rc = ICC_AES_CCM_Decrypt(ockCtx, iv, ivLen, key, keyLen, aad, aadLen,
                             ciphertext, ciphertextLen, plaintext,
                             &plaintextLen, tagLen);

    if (rc != ICC_OSSL_SUCCESS) {
        // entered an error condition here
        if (rc == -1) {
            // hash mismatch error
            ockCheckStatus(ockCtx);
            return ICC_AES_CCM_TAG_MISMATCH;
        } else {
            // generic error condition
            ockCheckStatus(ockCtx);
            return ICC_AES_CCM_CRYPTFINAL_FAILED;
        }
    }

    return 0;
}

/*
 *  Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  Method:    do_CCM_decryptFastJNI_WithHardwareSupport
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1CCM_1decryptFastJNI_1WithHardwareSupport(
    JNIEnv* env, jclass unusedClass, jint keyLen, jint ivLen,
    jint ciphertextOffset, jint ciphertextLen, jint plaintextOffset,
    jint aadLen, jint tagLen, jlong parameterBuffer, jbyteArray inputJ,
    jint inputOffset, jbyteArray outputJ, jint outputOffset) {
    // Setting static values
    int            J0Offset           = 64;
    int            blockSize          = 16;
    int            counterValueOffset = 12;
    int            tagOffset          = 16;
    int            keyOffset          = 80;
    int            ret                = -1;
    long           mode               = 0;
    long           len                = 0;
    long           alen               = 0;
    jboolean       isCopy             = 0;
    unsigned char* input              = NULL;
    unsigned char* output             = NULL;
    unsigned char* parameters         = NULL;
    unsigned char* iv                 = NULL;
    unsigned char* aad                = NULL;
    unsigned char* parm_block         = NULL;

    // Getting params
    if (inputJ != NULL) {
        input = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, inputJ,
                                                                   &isCopy));
    }
    if (outputJ != NULL) {
        output = (unsigned char*)((*env)->GetPrimitiveArrayCritical(
            env, outputJ, &isCopy));
    }
    parameters = (unsigned char*)parameterBuffer;
    iv         = parameters;
    aad        = parameters + ivLen;
    mode       = *((long long*)(parameters + ivLen + aadLen +
                          tagLen));  // Assuming sizeof(long) == 8. In 31 bit
                                     // mode a long is 4 bytes, long long is 8
                                     // bytes in both 31 and 64.
    parm_block = (unsigned char*)parameters + ivLen + aadLen + tagLen + 8;
    len        = ciphertextLen;
    alen       = aadLen;

    // Handle IV (different implementation based on the IV size)
    handleIV_CCM(ivLen, keyLen, blockSize, J0Offset, (char*)iv,
                 (char*)(parm_block + keyOffset), (char*)parm_block);
    memcpy(parm_block + counterValueOffset,
           parm_block + J0Offset + blockSize - 4, 4);  // Add Counter Value

    CCMzS390((input != NULL) ? (input + inputOffset) : NULL,
             (output != NULL) ? (output + outputOffset) : NULL, aad, &len,
             &alen, parm_block, &mode);

    ret = checkTagMismatch_CCM(
        (input != NULL) ? (char*)(input + inputOffset) : NULL, len,
        (char*)parm_block, tagOffset, tagLen);

    if (input != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, inputJ, input, 0);
    }
    if (output != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, outputJ, output, 0);
    }

    return ret;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_CCM_decryptFastJNI
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1CCM_1decryptFastJNI(
    JNIEnv* env, jclass unusedClass, jlong ockContextId, jint keyLen,
    jint ivLen, jint ciphertextLen, jint plaintextLen, jint aadLen, jint tagLen,
    jlong parameterBuffer, jlong inputBuffer, jlong outputBuffer) {
    ICC_CTX*       ockCtx     = (ICC_CTX*)((intptr_t)ockContextId);
    unsigned char* parameters = (unsigned char*)parameterBuffer;
    unsigned char* ciphertext = (unsigned char*)inputBuffer;
    unsigned char* plaintext  = (unsigned char*)outputBuffer;
    unsigned char* iv         = parameters;
    unsigned char* aad        = parameters + ivLen;
    unsigned char* key        = parameters + ivLen + aadLen;
    int            ret        = -1;

    ret = CCM_decrypt_core(env, ockCtx, key, keyLen, iv, ivLen, ciphertext,
                           ciphertextLen, plaintext, plaintextLen, aad, aadLen,
                           tagLen);

    return (jint)ret;
}

/*
 *  Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 *  Method:    do_CCM_decrypt
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1CCM_1decrypt(
    JNIEnv* env, jclass thisObj, jlong ockContextId, jbyteArray iv, jint ivLen,
    jbyteArray key, jint keyLen, jbyteArray aad, jint aadLen,
    jbyteArray ciphertext, jint ciphertextLen, jbyteArray plaintext,
    jint plaintextLen, jint tagLen) {
    static const char* functionName     = "NativeInterface.do_CCM_decrypt";
    ICC_CTX*           ockCtx           = (ICC_CTX*)((intptr_t)ockContextId);
    unsigned char*     keyNative        = NULL;
    unsigned char*     ivNative         = NULL;
    unsigned char*     plaintextNative  = NULL;
    unsigned char*     ciphertextNative = NULL;
    unsigned char*     aadNative        = NULL;
    int                rc               = ICC_OSSL_SUCCESS;
    int                ret              = -1;
    jboolean           isCopy           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    ivNative =
        (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv, &isCopy));
    keyNative =
        (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));
    ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    plaintextNative  = (unsigned char*)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));
    aadNative =
        (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, &isCopy));

    rc = (ivNative == NULL || keyNative == NULL || ciphertextNative == NULL ||
          plaintextNative == NULL || aadNative == NULL)
             ? ICC_OSSL_FAILURE
             : ICC_OSSL_SUCCESS;
#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM rc after PrimitiveArrayCritical %d", (int)rc);
    }
#endif
    if (rc == ICC_OSSL_SUCCESS) {
        ret = CCM_decrypt_core(env, ockCtx, keyNative, keyLen, ivNative, ivLen,
                               ciphertextNative, ciphertextLen, plaintextNative,
                               plaintextLen, aadNative, aadLen, tagLen);
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (keyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
    }

    if (ciphertextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative,
                                              0);
    }

    if (plaintextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative,
                                              0);
    }

    if (aadNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

#ifdef DEBUG_CCM_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CCM ret=%d", (int)ret);
    }
#endif
    if (debug) {
        gslogFunctionExit(functionName);
    }

    return (jint)ret;
}

/*============================================================================
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    internal functions
 * Signature:
 */
int CCM_encrypt_core(JNIEnv* env, ICC_CTX* ockCtx, unsigned char* key,
                     int keyLen, unsigned char* iv, int ivLen,
                     unsigned char* aad, int aadLen, int tagLen,
                     unsigned char* plainText, int plaintextLen,
                     unsigned char* cipherText, unsigned long ciphertextLen) {
    int                rc           = ICC_OSSL_SUCCESS;
    static const char* functionName = "NativeInterface.CCM_encrypt_core";

    if (debug) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_CCM_DATA
    if (debug) {
        gslogMessagePrefix("DATA_CCM iv : ");
        gslogMessageHex((char*)iv, 0, (int)ivLen, 0, 0, NULL);

        gslogMessagePrefix("DATA_CCM key : ");
        gslogMessageHex((char*)key, 0, (int)keyLen, 0, 0, NULL);

        gslogMessagePrefix("DATA_CCM plainText : ");
        gslogMessageHex((char*)plainText, 0, (int)plaintextLen, 0, 0, NULL);

        gslogMessagePrefix("DATA_CCM aad : ");
        gslogMessageHex((char*)aad, 0, (int)aadLen, 0, 0, NULL);
    }
#endif
    rc = ICC_AES_CCM_Encrypt(ockCtx, iv, ivLen, key, keyLen, aad, aadLen,
                             plainText, plaintextLen, cipherText,
                             &ciphertextLen, tagLen);

    if (rc != ICC_OSSL_SUCCESS) {
        ockCheckStatus(ockCtx);
        return ICC_AES_CCM_CRYPTFINAL_FAILED;
    }

    return 0;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_CCM_checkHardwareCCMSupport
 */
FUNC* JCC_OS_helpers(ICC_CTX* ctx);
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1CCM_1checkHardwareCCMSupport(
    JNIEnv* env, jclass unusedClass, jlong ockContextId) {
    ICC_CTX* ctx     = (ICC_CTX*)((intptr_t)ockContextId);
    FUNC*    funcPtr = ICC_OS_helpers(ctx);

    if ((NULL == funcPtr) || (NULL == funcPtr[1].func) ||
        (NULL == funcPtr[1].name)) {
        return -1;
    } else {
        CCMECB   = (ECB_FuncPtr)funcPtr[3].func;    // z_km_native_CCM
        CCMGHASH = (GHASH_FuncPtr)funcPtr[4].func;  // z_kimd_native_CCM
        CCMzS390 = (zS390_FuncPtr)funcPtr[1].func;  // s390_kmccm_native
        return 1;
    }
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_CCM_encryptFastJNI_WithHardwareSupport
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1CCM_1encryptFastJNI_1WithHardwareSupport(
    JNIEnv* env, jclass unusedClass, jint keyLen, jint ivLen,
    jint plaintextOffset, jint plaintextLen, jint ciphertextOffset, jint aadLen,
    jint tagLen, jlong parameterBuffer, jbyteArray inputJ, jint inputOffset,
    jbyteArray outputJ, jint outputOffset) {
    long           mode               = 0;
    long           len                = 0;
    long           alen               = 0;
    jboolean       isCopy             = 0;
    int            J0Offset           = 64;
    int            blockSize          = 16;
    int            counterValueOffset = 12;
    int            keyOffset          = 80;
    unsigned char* input              = NULL;
    unsigned char* output             = NULL;
    unsigned char* parameters         = NULL;
    unsigned char* iv                 = NULL;
    unsigned char* aad                = NULL;
    unsigned char* parm_block         = NULL;
    unsigned char* tag                = NULL;

    // Getting params
    if (inputJ != NULL) {
        input = (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, inputJ,
                                                                   &isCopy));
    }
    if (outputJ != NULL) {
        output = (unsigned char*)((*env)->GetPrimitiveArrayCritical(
            env, outputJ, &isCopy));
    }
    parameters = (unsigned char*)parameterBuffer;
    iv         = parameters;
    aad        = parameters + ivLen;
    mode       = *((long long*)(parameters + ivLen + aadLen +
                          tagLen));  // Assuming sizeof(long) == 8. In 31 bit
                                     // mode a long is 4 bytes, long long is 8
                                     // bytes in both 31 and 64.
    parm_block = parameters + ivLen + aadLen + tagLen + 8;
    len        = plaintextLen;
    alen       = aadLen;

    // Handle IV (different implementation based on the IV size)
    handleIV_CCM(ivLen, keyLen, blockSize, J0Offset, (char*)iv,
                 (char*)(parm_block + keyOffset), (char*)parm_block);
    memcpy(parm_block + counterValueOffset,
           parm_block + J0Offset + blockSize - 4, 4);  // Add Counter Value

    CCMzS390((input != NULL) ? (input + inputOffset) : NULL,
             (output != NULL) ? (output + outputOffset) : NULL, aad, &len,
             &alen, parm_block, &mode);

    // Copy tag
    tag = parameters + ivLen + aadLen + keyLen;
    memcpy(tag, parm_block + 16, tagLen);  // Add tag to output

    if (input != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, inputJ, input, 0);
    }
    if (output != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, outputJ, output, 0);
    }

    return 0;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_CCM_encryptFastJNI
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1CCM_1encryptFastJNI(
    JNIEnv* env, jclass unusedClass, jlong ockContextId, jint keyLen,
    jint ivLen, jint plaintextLen, jint ciphertextLen, jint aadLen, jint tagLen,
    jlong parameterBuffer, jlong inputBuffer, jlong outputBuffer) {
    ICC_CTX*       ockCtx           = (ICC_CTX*)((intptr_t)ockContextId);
    unsigned char* parameters       = (unsigned char*)parameterBuffer;
    unsigned char* plaintextNative  = (unsigned char*)inputBuffer;
    unsigned char* ciphertextNative = (unsigned char*)outputBuffer;
    unsigned char* iv               = parameters;
    unsigned char* aad              = parameters + ivLen;
    unsigned char* key              = parameters + ivLen + aadLen;
    int            ret              = -1;

    ret = CCM_encrypt_core(env, ockCtx, key, keyLen, iv, ivLen, aad, aadLen,
                           tagLen, plaintextNative, plaintextLen,
                           ciphertextNative, ciphertextLen);

    return (jint)ret;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    do_CCM_encrypt
 * Signature: (J[BI[BI[BII[BI[BI[B)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_do_1CCM_1encrypt(
    JNIEnv* env, jclass thisObj, jlong ockContextId, jbyteArray iv, jint ivLen,
    jbyteArray key, jint keyLen, jbyteArray aad, jint aadLen,
    jbyteArray plaintext, jint plaintextLen, jbyteArray ciphertext,
    jint ciphertextLen, jint tagLen) {
    static const char* functionName     = "NativeInterface.do_CCM_encrypt";
    ICC_CTX*           ockCtx           = (ICC_CTX*)((intptr_t)ockContextId);
    unsigned char*     keyNative        = NULL;
    unsigned char*     ivNative         = NULL;
    unsigned char*     plaintextNative  = NULL;
    unsigned char*     ciphertextNative = NULL;
    unsigned char*     aadNative        = NULL;
    int                rc               = ICC_OSSL_SUCCESS;
    int                ret              = -1;
    jboolean           isCopy           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    ivNative =
        (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, iv, &isCopy));
    keyNative =
        (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, key, &isCopy));
    if (plaintextLen > 0) {
        plaintextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(
            env, plaintext, &isCopy));
    }
    ciphertextNative = (unsigned char*)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    aadNative =
        (unsigned char*)((*env)->GetPrimitiveArrayCritical(env, aad, &isCopy));

    rc = (ivNative == NULL || keyNative == NULL || ciphertextNative == NULL ||
          aadNative == NULL)
             ? ICC_OSSL_FAILURE
             : ICC_OSSL_SUCCESS;

    if (rc == ICC_OSSL_SUCCESS) {
        ret = CCM_encrypt_core(env, ockCtx, keyNative, keyLen, ivNative, ivLen,
                               aadNative, aadLen, tagLen, plaintextNative,
                               plaintextLen, ciphertextNative, ciphertextLen);
    } else {
        ret = GetPRIMITICEARRAYCRITICAL;
    }

    if (keyNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, key, keyNative, 0);
    }

    if (ivNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, iv, ivNative, 0);
    }

    if (aadNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, aad, aadNative, 0);
    }

    if (plaintextNative != NULL && plaintextLen > 0) {
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

    return (jint)ret;
}

int OpenSSLError(ICC_CTX* ICC_ctx, const int line) {
    char buf1[8192];

    unsigned long retcode = 0;
    retcode               = ICC_ERR_get_error(ICC_ctx);

    /* While because we want to drain the swamp */
    while (0 != retcode && ((unsigned long)-2L) != retcode) {
        ICC_ERR_error_string(ICC_ctx, retcode, (char*)buf1);
        printf("OpenSSL error line %d [%s]\n", line, buf1);
        retcode = ICC_ERR_get_error(ICC_ctx);
    }
    return retcode;
}
