/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLUtils.c
 * @brief Core utility implementations for OpenSSL JNI operations.
 *
 * This file implements the fundamental utility functions used throughout
 * the OpenSSL native code, including:
 * - Exception handling and error reporting
 * - OpenSSL error string extraction and logging
 * - Common validation helpers for adapter-selected context markers
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "OpenSSLContext.h"
#include "OpenSSLExceptionCodes.h"
#include "OpenSSLUtils.h"
#include "OpenSSLSymmetricCipher.h"
#include "OpenSSLHelpers.h"

/* Buffer size for OpenSSL error strings */
#define OPENSSL_ERROR_STRING_SIZE 256

/* Buffer size for logging messages */
#define LOG_BUFFER_SIZE 4096

/* Context ID constants */
#define CONTEXT_ID_NON_FIPS 1
#define CONTEXT_ID_FIPS     2

int debug = 0;

static int isFIPSSupported(void);

static int isFIPSSupported(void) {
    OSSL_LIB_CTX* testCtx = OSSL_LIB_CTX_new();
    if (testCtx == NULL) {
        return 0;
    }

    OSSL_PROVIDER* fips      = OSSL_PROVIDER_load(testCtx, "fips");
    int            supported = (fips != NULL);

    if (fips != NULL) {
        OSSL_PROVIDER_unload(fips);
    }
    OSSL_LIB_CTX_free(testCtx);

    return supported;
}

OpenSSLContext* createContext(JNIEnv* env, int isFIPS) {
    static const char* functionName = "OpenSSLUtils.createContext";

    logFunctionEntry(functionName);

    if (isFIPS && !isFIPSSupported()) {
        setPendingOpenSSLException(
            env, OPENSSL_FIPS_MODE_INVALID,
            "FIPS mode requested but FIPS provider is not available");
        logFunctionExit(functionName);
        return NULL;
    }

    OpenSSLContext* context = (OpenSSLContext*)mallocSafe(
        env, sizeof(OpenSSLContext),
        "Failed to allocate memory for OpenSSL context");
    if (context == NULL) {
        logFunctionExit(functionName);
        return NULL;
    }

    // Memory already zeroed by mallocSafe
    context->id = isFIPS ? CONTEXT_ID_FIPS : CONTEXT_ID_NON_FIPS;

    context->libctx = OSSL_LIB_CTX_new();
    if (context->libctx == NULL) {
        free(context);
        setPendingOpenSSLException(env, OPENSSL_LIBRARY_LOAD_FAILED,
                              "Failed to create OpenSSL library context");
        logOpenSSLError("OSSL_LIB_CTX_new");
        logFunctionExit(functionName);
        return NULL;
    }

    if (isFIPS) {
        context->fips = OSSL_PROVIDER_load(context->libctx, "fips");
        if (context->fips == NULL) {
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            setPendingOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                                  "Failed to load FIPS provider");
            logOpenSSLError("OSSL_PROVIDER_load(fips)");
            logFunctionExit(functionName);
            return NULL;
        }

        if (EVP_default_properties_enable_fips(context->libctx, 1) != 1) {
            OSSL_PROVIDER_unload(context->fips);
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            setPendingOpenSSLException(env, OPENSSL_FIPS_MODE_INVALID,
                                  "Failed to enable FIPS mode");
            logOpenSSLError("EVP_default_properties_enable_fips");
            logFunctionExit(functionName);
            return NULL;
        }

        context->base = OSSL_PROVIDER_load(context->libctx, "base");
        if (context->base == NULL) {
            OSSL_PROVIDER_unload(context->fips);
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            setPendingOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                                  "Failed to load base provider");
            logOpenSSLError("OSSL_PROVIDER_load(base)");
            logFunctionExit(functionName);
            return NULL;
        }

#ifdef DEBUG_OPENSSL_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_OPENSSL FIPS provider and base provider loaded, FIPS "
                "mode enabled");
        }
#endif
    } else {
        context->defaultProv = OSSL_PROVIDER_load(context->libctx, "default");
        if (context->defaultProv == NULL) {
            OSSL_LIB_CTX_free(context->libctx);
            free(context);
            setPendingOpenSSLException(env, OPENSSL_PROVIDER_LOAD_FAILED,
                                  "Failed to load default provider");
            logOpenSSLError("OSSL_PROVIDER_load(default)");
            logFunctionExit(functionName);
            return NULL;
        }

#ifdef DEBUG_OPENSSL_DETAIL
        if (debug) {
            gslogMessage("DETAIL_OPENSSL Default provider loaded");
        }
#endif
    }

#ifdef DEBUG_OPENSSL_DETAIL
    if (debug) {
        gslogMessage(
            "DETAIL_OPENSSL OpenSSL context created successfully (ID: %ld)",
            context->id);
    }
#endif

    logFunctionExit(functionName);
    return context;
}

void freeInternalContext(OpenSSLContext* context) {
    if (context != NULL) {
        if (context->fips != NULL) {
            OSSL_PROVIDER_unload(context->fips);
        }
        if (context->defaultProv != NULL) {
            OSSL_PROVIDER_unload(context->defaultProv);
        }
        if (context->base != NULL) {
            OSSL_PROVIDER_unload(context->base);
        }
        if (context->libctx != NULL) {
            OSSL_LIB_CTX_free(context->libctx);
        }
        free(context);
    }
}

int validateCipherContext(JNIEnv* env, jint fipsFlag, jlong cipherId,
                          const char*     functionName,
                          CipherContext** outCipherCtx) {
    CipherContext* cipherCtx = (CipherContext*)cipherId;

    if (cipherCtx == NULL || cipherCtx->ctx == NULL ||
        cipherCtx->cipher == NULL) {
        setPendingOpenSSLException(env, OPENSSL_UNSPECIFIED,
                              "Invalid cipher context ID");
        logFunctionExit(functionName);
        return 0;
    }

    if (outCipherCtx != NULL) {
        *outCipherCtx = cipherCtx;
    }

    return 1;
}

static jclass    openSSLExceptionClass               = NULL;
static jmethodID openSSLExceptionConstructor         = NULL;
static jmethodID openSSLExceptionConstructorWithCode = NULL;

/* R-2: Called from JNI_OnLoad to eagerly cache the exception class GlobalRef
 * and both constructors. This eliminates the lazy-init data race that would
 * occur if two threads threw exceptions before any prior call. */
void initOpenSSLExceptionClass(JNIEnv* env) {
    if (openSSLExceptionClass != NULL) {
        return; /* Already initialised */
    }
    jclass localRef = (*env)->FindClass(
        env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
    if (localRef == NULL) {
        return; /* FindClass threw NoClassDefFoundError — nothing we can do */
    }
    jclass globalRef = (*env)->NewGlobalRef(env, localRef);
    (*env)->DeleteLocalRef(env, localRef);
    if (globalRef == NULL) {
        return; /* OutOfMemoryError already thrown */
    }
    jmethodID ctor1 = (*env)->GetMethodID(
        env, globalRef, "<init>", "(Ljava/lang/String;)V");
    jmethodID ctor2 = (*env)->GetMethodID(
        env, globalRef, "<init>", "(Ljava/lang/String;I)V");
    if (ctor1 == NULL || ctor2 == NULL) {
        (*env)->DeleteGlobalRef(env, globalRef);
        return; /* GetMethodID failed */
    }
    openSSLExceptionClass               = globalRef;
    openSSLExceptionConstructor         = ctor1;
    openSSLExceptionConstructorWithCode = ctor2;
}

/* Called by JNI_OnUnload to release the global reference. */
void cleanupOpenSSLExceptionClass(JNIEnv* env) {
    if (openSSLExceptionClass != NULL) {
        (*env)->DeleteGlobalRef(env, openSSLExceptionClass);
        openSSLExceptionClass               = NULL;
        openSSLExceptionConstructor         = NULL;
        openSSLExceptionConstructorWithCode = NULL;
    }
}

void setPendingOpenSSLException(JNIEnv* env, int code, const char* msg) {
    jstring jMsg;

    // Don't throw a second exception if one is already pending
    // This prevents corrupting the exception state
    if ((*env)->ExceptionCheck(env)) {
        return;
    }

    /* R-2: openSSLExceptionClass is initialised by initOpenSSLExceptionClass()
     * called from JNI_OnLoad. Fall back to lazy init only if somehow not yet
     * done (e.g. direct native call in tests). */
    if (openSSLExceptionClass == NULL) {
        jclass localRef = (*env)->FindClass(
            env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
        if (localRef == NULL) {
            return;  /* Exception already thrown */
        }
        openSSLExceptionClass = (*env)->NewGlobalRef(env, localRef);
        (*env)->DeleteLocalRef(env, localRef);
        if (openSSLExceptionClass == NULL) {
            return;  /* NewGlobalRef failed (OutOfMemoryError) */
        }
        openSSLExceptionConstructor = (*env)->GetMethodID(
            env, openSSLExceptionClass, "<init>", "(Ljava/lang/String;)V");
        openSSLExceptionConstructorWithCode = (*env)->GetMethodID(
            env, openSSLExceptionClass, "<init>", "(Ljava/lang/String;I)V");
        if (openSSLExceptionConstructor == NULL ||
            openSSLExceptionConstructorWithCode == NULL) {
            return;  /* GetMethodID failed (exception already set) */
        }
    }

    jMsg = (*env)->NewStringUTF(env, msg);
    if (jMsg == NULL) {
        return;  // OutOfMemoryError already thrown
    }

    jobject exception;
    if (code != 0) {
        exception =
            (*env)->NewObject(env, openSSLExceptionClass,
                              openSSLExceptionConstructorWithCode, jMsg, code);
    } else {
        exception = (*env)->NewObject(env, openSSLExceptionClass,
                                      openSSLExceptionConstructor, jMsg);
    }

    if (exception != NULL) {
        (*env)->Throw(env, exception);
    }
}

char* getOpenSSLErrorString(void) {
    char* buf = malloc(OPENSSL_ERROR_STRING_SIZE);
    if (buf == NULL) {
        return NULL;
    }

    unsigned long err = ERR_get_error();
    if (err == 0) {
        strcpy(buf, "No OpenSSL error");
    } else {
        ERR_error_string_n(err, buf, OPENSSL_ERROR_STRING_SIZE);
    }

    return buf;
}

void logOpenSSLError(const char* prefix) {
    if (debug) {
        char* errStr = getOpenSSLErrorString();
        if (errStr != NULL) {
            fprintf(stderr, "%s: %s\n", prefix, errStr);
            free(errStr);
        }
    }
}

void logHexData(const unsigned char* data, int length, const char* prefix) {
    /* Number of bytes to display per line in hex dumps */
    const int BYTES_PER_LINE = 16;

    if (debug && data != NULL && length > 0) {
        fprintf(stderr, "%s: ", prefix);
        for (int i = 0; i < length; i++) {
            fprintf(stderr, "%02x", data[i]);
            if ((i + 1) % BYTES_PER_LINE == 0 && i < length - 1) {
                fprintf(stderr, "\n%s: ", prefix);
            } else if (i < length - 1) {
                fprintf(stderr, " ");
            }
        }
        fprintf(stderr, "\n");
    }
}

jclass getOpenSSLExceptionClass(JNIEnv* env) {
    /* openSSLExceptionClass is already a GlobalRef once set by
     * setPendingOpenSSLException; just return it if available. */
    if (openSSLExceptionClass != NULL) {
        return openSSLExceptionClass;
    }
    /* Not yet initialised — go through setPendingOpenSSLException's
     * init path by fetching and promoting to a GlobalRef ourselves. */
    jclass localRef = (*env)->FindClass(
        env, "com/ibm/crypto/plus/provider/openssl/OpenSSLException");
    if (localRef == NULL) {
        return NULL;
    }
    jclass globalRef = (*env)->NewGlobalRef(env, localRef);
    (*env)->DeleteLocalRef(env, localRef);
    if (globalRef == NULL) {
        return NULL;  /* OutOfMemoryError already thrown */
    }
    openSSLExceptionClass = globalRef;
    return openSSLExceptionClass;
}

int gslogFunctionEntry(const char* functionName) {
    return gslogMessage("Entering %s", functionName);
}

int gslogError(const char* formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    char        printBuffer[LOG_BUFFER_SIZE];

    if (!debug) {
        return 0;
    }

    va_start(formatArgs, formatString);
    charsPrinted =
        vsnprintf(printBuffer, sizeof(printBuffer), formatString, formatArgs);

    fprintf(stderr, "[ERROR] %s\n", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

int gslogMessage(const char* formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    char        printBuffer[LOG_BUFFER_SIZE];

    if (!debug) {
        return 0;
    }

    va_start(formatArgs, formatString);
    charsPrinted =
        vsnprintf(printBuffer, sizeof(printBuffer), formatString, formatArgs);

    fprintf(stderr, "[DEBUG] %s\n", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

int gslogMessagePrefix(const char* formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    char        printBuffer[LOG_BUFFER_SIZE];

    if (!debug) {
        return 0;
    }

    va_start(formatArgs, formatString);
    charsPrinted =
        vsnprintf(printBuffer, sizeof(printBuffer), formatString, formatArgs);

    fprintf(stderr, "[DEBUG] %s", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

int gslogMessageHex(char bytes[], int offset, int length, int spaceAfter,
                    int newlineAfter, char* newlinePrefix) {
    int index;
    int charsPrinted = 0;

    for (index = 1; index <= length; index++) {
        charsPrinted +=
            fprintf(stderr, "%2.2X", (unsigned char)bytes[offset + index - 1]);
        if ((newlineAfter > 0) && ((index % newlineAfter) == 0) &&
            (index < length)) {
            charsPrinted += fprintf(stderr, "\n");
            if (newlinePrefix != NULL) {
                charsPrinted += fprintf(stderr, "%s", newlinePrefix);
            }
        } else if ((spaceAfter > 0) && ((index % spaceAfter) == 0)) {
            charsPrinted += fprintf(stderr, " ");
        }
    }
    charsPrinted += fprintf(stderr, "\n");
    fflush(stderr);
    return charsPrinted;
}

int gslogFunctionExit(const char* functionName) {
    return gslogMessage("Exiting %s", functionName);
}
