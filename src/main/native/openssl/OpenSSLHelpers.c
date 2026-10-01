/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLHelpers.c
 * @brief Implementation of common helper functions for OpenSSL JNI operations.
 *
 * This file implements utility functions that are used across all OpenSSL
 * native code to provide consistent error handling, parameter validation,
 * resource management, and JNI operations.
 *
 * The helpers are organized into functional groups:
 * - Logging: Debug logging with function entry/exit tracking
 * - Context validation and management
 * - String handling: Safe UTF-8 string conversion and cleanup
 * - Byte array handling: Safe JNI array access and cleanup
 * - Validation: Parameter range and bounds checking
 * - OpenSSL objects: Safe fetching and creation of EVP objects
 * - Memory: Safe allocation with error handling
 * - AAD processing: Common authenticated encryption data handling
 */

#include "OpenSSLHelpers.h"
#include "OpenSSLGCM.h"

//============================================================================
// Logging Helpers
//============================================================================

void logFunctionEntry(const char* functionName) {
    if (debug) {
        gslogFunctionEntry(functionName);
    }
}

void logFunctionExit(const char* functionName) {
    if (debug) {
        gslogFunctionExit(functionName);
    }
}

//============================================================================
// Context Validation
//============================================================================

/* Contexts initialised by initializeOpenSSLContexts().
 * Pointers start NULL; they are set once from OpenSSLJNI.c on first use
 * so that EVP_CIPHER_fetch / EVP_MD_fetch / EVP_RAND_fetch use the correct
 * OSSL_LIB_CTX rather than the global context.
 *
 * Access is protected by g_contextMutex to prevent race conditions when
 * multiple threads trigger context initialisation simultaneously. */
#ifdef _WIN32
#include <windows.h>
static CRITICAL_SECTION g_contextMutex;
static INIT_ONCE        g_mutexInitOnce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK    initMutexCallback(PINIT_ONCE initOnce, PVOID param, PVOID* context) {
    (void)initOnce; (void)param; (void)context;
    InitializeCriticalSection(&g_contextMutex);
    return TRUE;
}
static void contextMutexLock(void) {
    /* Thread-safe one-time initialisation using INIT_ONCE (Vista+). */
    InitOnceExecuteOnce(&g_mutexInitOnce, initMutexCallback, NULL, NULL);
    EnterCriticalSection(&g_contextMutex);
}
static void contextMutexUnlock(void) {
    LeaveCriticalSection(&g_contextMutex);
}
#else
#include <pthread.h>
static pthread_mutex_t g_contextMutex = PTHREAD_MUTEX_INITIALIZER;
static void contextMutexLock(void)   { pthread_mutex_lock(&g_contextMutex);   }
static void contextMutexUnlock(void) { pthread_mutex_unlock(&g_contextMutex); }
#endif

static OpenSSLContext* g_nonFipsContext = NULL;
static OpenSSLContext* g_fipsContext    = NULL;

void initializeOpenSSLContexts(OpenSSLContext* nonFips, OpenSSLContext* fips) {
    contextMutexLock();
    /* Only overwrite a slot when a non-NULL value is supplied; a NULL
     * argument means "leave the existing pointer unchanged". */
    if (nonFips != NULL) {
        g_nonFipsContext = nonFips;
    }
    if (fips != NULL) {
        g_fipsContext = fips;
    }
    contextMutexUnlock();
}

int validateAndGetContext(JNIEnv* env, jint fipsFlag, const char* functionName,
                          OpenSSLContext** outContext) {
    contextMutexLock();
    OpenSSLContext* context = (fipsFlag != 0) ? g_fipsContext : g_nonFipsContext;

    if (context == NULL) {
        /* Contexts not yet initialised — fall back to creating on demand. */
        contextMutexUnlock();
        context = createContext(env, (fipsFlag != 0));
        if (context == NULL) {
            /* createContext already set the exception */
            return 0;
        }
        contextMutexLock();
        /* Re-check: another thread may have initialised while we were creating */
        OpenSSLContext* existing = (fipsFlag != 0) ? g_fipsContext : g_nonFipsContext;
        if (existing != NULL) {
            /* Lost the race — free the duplicate context we just created. */
            freeInternalContext(context);
            context = existing;
        } else {
            if (fipsFlag != 0) {
                g_fipsContext = context;
            } else {
                g_nonFipsContext = context;
            }
        }
    }
    contextMutexUnlock();

    if (outContext != NULL) {
        *outContext = context;
    }

    return 1;
}

//============================================================================
// String Helpers
//============================================================================

const char* getStringUTFCharsSafe(JNIEnv* env, jstring javaString,
                                  const char* functionName,
                                  const char* errorMsg) {
    if (javaString == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }

    const char* str = (*env)->GetStringUTFChars(env, javaString, NULL);
    if (str == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                              "Failed to get UTF string");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }

    return str;
}

void cleanupStringUTFChars(JNIEnv* env, jstring javaString, const char* str) {
    if (str != NULL && javaString != NULL) {
        (*env)->ReleaseStringUTFChars(env, javaString, str);
    }
}

//============================================================================
// Byte Array Helpers
//============================================================================

jbyte* getByteArrayElementsSafe(JNIEnv* env, jbyteArray array,
                                const char* functionName,
                                const char* errorMsg) {
    if (array == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }

    jbyte* bytes = (*env)->GetByteArrayElements(env, array, NULL);
    if (bytes == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED,
                              "Failed to get byte array elements");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }

    return bytes;
}

void cleanupByteArray(JNIEnv* env, jbyteArray array, jbyte* bytes, jint mode) {
    if (bytes != NULL && array != NULL) {
        (*env)->ReleaseByteArrayElements(env, array, bytes, mode);
    }
}

void cleanupByteArrays(JNIEnv* env, jbyteArray keyArray, jbyte* keyBytes,
                       jbyteArray ivArray, jbyte* ivBytes) {
    if (keyBytes != NULL && keyArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, keyArray, keyBytes, JNI_ABORT);
    }
    if (ivBytes != NULL && ivArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, ivArray, ivBytes, JNI_ABORT);
    }
}

void cleanupIOArrays(JNIEnv* env, jbyteArray inputArray, jbyte* inputBytes,
                     jbyteArray outputArray, jbyte* outputBytes,
                     jboolean commitOutput) {
    if (inputBytes != NULL && inputArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, inputArray, inputBytes,
                                         JNI_ABORT);
    }
    if (outputBytes != NULL && outputArray != NULL) {
        (*env)->ReleaseByteArrayElements(env, outputArray, outputBytes,
                                         commitOutput ? 0 : JNI_ABORT);
    }
}

//============================================================================
// Validation Helper Functions
//============================================================================

int validateIntRange(JNIEnv* env, jint value, jint min, jint max,
                     const char* functionName, const char* errorMsg) {
    if (value < min || value > max) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    return 1;
}

int validateArrayLength(JNIEnv* env, jbyteArray array, jint min, jint max,
                        const char* functionName, const char* errorMsg) {
    jsize length = (*env)->GetArrayLength(env, array);
    if (length < min || length > max) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    return 1;
}

int validateOutputBuffer(JNIEnv* env, jbyteArray output, jint outputOffset,
                         jint requiredSize, const char* functionName,
                         const char* errorMsg) {
    if (output == NULL || outputOffset < 0) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    jsize outputLength = (*env)->GetArrayLength(env, output);
    if ((jlong)outputOffset + (jlong)requiredSize > (jlong)outputLength) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    return 1;
}

int validateOffsetAndLength(JNIEnv* env, jint arrayLength, jint offset,
                            jint length, const char* functionName,
                            const char* errorMsg) {
    // Check for negative values first
    if (offset < 0 || length < 0) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    // Check for overflow: offset + length must not overflow and must fit in array
    // Using explicit separate checks to prevent any potential integer overflow
    // in the comparison operations themselves
    if (offset > arrayLength) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    
    if (length > arrayLength) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }
    
    // Now safe to check: offset + length <= arrayLength
    // Rewritten as: length <= arrayLength - offset (already validated offset <= arrayLength)
    if (length > arrayLength - offset) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER, errorMsg);
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    return 1;
}

//============================================================================
// OpenSSL Object Fetch Helpers
//============================================================================

EVP_CIPHER_CTX* createCipherCtxSafe(JNIEnv* env, const char* functionName,
                                    int errorCode, const char* errorMsg) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        setPendingOpenSSLException(env, errorCode, errorMsg);
        logOpenSSLError("EVP_CIPHER_CTX_new");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return NULL;
    }
    return ctx;
}

//============================================================================
// Memory Helpers
//============================================================================

void* mallocSafe(JNIEnv* env, size_t size, const char* errorMsg) {
    void* ptr = malloc(size);
    if (ptr == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED, errorMsg);
        return NULL;
    }
    memset(ptr, 0, size);
    return ptr;
}

jbyteArray newByteArraySafe(JNIEnv* env, jsize length, const char* errorMsg) {
    jbyteArray array = (*env)->NewByteArray(env, length);
    if (array == NULL) {
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED, errorMsg);
        return NULL;
    }
    return array;
}

//============================================================================
// AAD Processing Helper (for GCM/CCM)
//============================================================================

int processAAD(JNIEnv* env, EVP_CIPHER_CTX* ctx, const unsigned char* aad,
               int aadLen, const char* functionName) {
    // Validate cipher context first
    if (ctx == NULL) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "Cipher context is NULL");
        logFunctionExit(functionName);
        return 0;
    }

    // No AAD to process is valid (AAD is optional)
    if (aad == NULL || aadLen <= 0) {
        return 1;
    }

    int outLen = 0;
    int result = EVP_CipherUpdate(ctx, NULL, &outLen, aad, aadLen);

    if (result != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to process AAD");
        logOpenSSLError("EVP_CipherUpdate(AAD)");
        logFunctionExit(functionName);
        return 0;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER AAD processed: %d bytes", aadLen);
    }
#endif

    return 1;
}

int processAADFromArray(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyteArray aad,
                        jint aadLen, const char* functionName) {
    // No AAD to process is valid (AAD is optional)
    if (aad == NULL || aadLen <= 0) {
        return 1;
    }

    /* Validate aadLen against the actual array length before pinning.
     * The caller supplies aadLen independently of the array; if it exceeds
     * the array size EVP_CipherUpdate would read past the pinned buffer. */
    if (aadLen > (*env)->GetArrayLength(env, aad)) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                                   "AAD length exceeds array size");
        if (debug && functionName != NULL) {
            gslogFunctionExit(functionName);
        }
        return 0;
    }

    jbyte* aadBytes = getByteArrayElementsSafe(env, aad, functionName, "AAD");
    if (aadBytes == NULL) {
        return 0;
    }

    int result =
        processAAD(env, ctx, (unsigned char*)aadBytes, aadLen, functionName);

    cleanupByteArray(env, aad, aadBytes, JNI_ABORT);

    return result;
}

int extractAndSetTag(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyteArray input,
                     jint inputOffset, jint inputLen, jint tagLen, int ctrlType,
                     const char* functionName) {
    if (input == NULL || inputLen < tagLen) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "Invalid input for tag extraction");
        logFunctionExit(functionName);
        return 0;
    }

    jbyte* inputBytes =
        getByteArrayElementsSafe(env, input, functionName, "input");
    if (inputBytes == NULL) {
        return 0;
    }

    // Tag is at the end of the input
    unsigned char* tag =
        (unsigned char*)(inputBytes + inputOffset + inputLen - tagLen);

    int result = EVP_CIPHER_CTX_ctrl(ctx, ctrlType, tagLen, tag);

    cleanupByteArray(env, input, inputBytes, JNI_ABORT);

    if (result != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to set authentication tag");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(SET_TAG)");
        logFunctionExit(functionName);
        return 0;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_CIPHER Tag extracted and set for verification: %d bytes",
            tagLen);
    }
#endif

    return 1;
}

int getAndAppendTag(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyte* outputBytes,
                    jint outputOffset, jint currentLen, jint tagLen,
                    int ctrlType, const char* functionName) {
    // Use MAX_GCM_TAG_SIZE constant (16 bytes) for maximum tag buffer size
    // This matches both GCM and CCM maximum tag sizes
    unsigned char tag[MAX_GCM_TAG_SIZE];

    if (tagLen > MAX_GCM_TAG_SIZE) {
        setPendingOpenSSLException(env, OPENSSL_INVALID_PARAMETER,
                              "Tag length exceeds maximum");
        logFunctionExit(functionName);
        return -1;
    }

    int result = EVP_CIPHER_CTX_ctrl(ctx, ctrlType, tagLen, tag);

    if (result != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_FINAL_FAILED,
                              "Failed to get authentication tag");
        logOpenSSLError("EVP_CIPHER_CTX_ctrl(GET_TAG)");
        logFunctionExit(functionName);
        return -1;
    }

    // Append tag to output
    memcpy(outputBytes + outputOffset + currentLen, tag, tagLen);

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER Tag generated and appended: %d bytes",
                     tagLen);
    }
#endif

    return currentLen + tagLen;
}

int processZeroLengthInput(JNIEnv* env, EVP_CIPHER_CTX* ctx, jbyte* outputBytes,
                           jint outputOffset, const char* functionName) {
    int outLen = 0;

    /* Pass NULL as the input pointer with length 0.  This is required by
     * OpenSSL for CCM mode when there is no ciphertext: passing a non-NULL
     * pointer would cause OpenSSL to skip the internal state finalisation
     * step needed before tag verification.  GCM tolerates either form, so
     * NULL is safe for both modes. */
    int result = EVP_CipherUpdate(
        ctx, (unsigned char*)(outputBytes + outputOffset), &outLen, NULL, 0);

    if (result != 1) {
        setPendingOpenSSLException(env, OPENSSL_CIPHER_UPDATE_FAILED,
                              "Failed to process zero-length input");
        logOpenSSLError("EVP_CipherUpdate(zero-length)");
        logFunctionExit(functionName);
        return 0;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessage("DETAIL_CIPHER Zero-length input processed");
    }
#endif

    return 1;
}
