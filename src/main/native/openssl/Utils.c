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
#include <openssl/err.h>

#include "Utils.h"
#include <string.h>

int debug = 0;  // FIXME

//============================================================================
//
//
int gslogFunctionEntry(const char *functionName) {
    return gslogMessage("Entering %s", functionName);
}

//============================================================================
//
//
int gslogError(const char *formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    char        printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsnprintf(printBuffer, sizeof(printBuffer), formatString, formatArgs);

    fprintf(stderr, "[ERROR] %s\n", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

//============================================================================
//
//
int gslogMessage(const char *formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    char        printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsnprintf(printBuffer, sizeof(printBuffer), formatString, formatArgs);

    fprintf(stderr, "[DEBUG] %s\n", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

//============================================================================
//
//
int gslogMessagePrefix(const char *formatString, ...) {
    int         charsPrinted;
    va_list     formatArgs;
    char        printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsnprintf(printBuffer, sizeof(printBuffer), formatString, formatArgs);

    fprintf(stderr, "[DEBUG] %s", printBuffer);

    va_end(formatArgs);
    fflush(stderr);
    return charsPrinted;
}

//============================================================================
//
//
int gslogMessageHex(char bytes[], int offset, int length, int spaceAfter,
                    int newlineAfter, char *newlinePrefix) {
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

//============================================================================
//
//
int gslogFunctionExit(const char *functionName) {
    return gslogMessage("Exiting %s", functionName);
}

//============================================================================
//
//
void osslCheckStatus(void) {
    unsigned long errCode;

    while ((errCode = ERR_get_error()) != 0) {
        char *err;
        // gslogMessage("Generating error message");
        err = ERR_error_string(errCode, NULL);
        gslogMessage("%s", err);
    }

}

//============================================================================
//
//
void throwOSSLException(JNIEnv *env, int code, const char *msg) {
#define EXCEPTION_CLASS "com/ibm/crypto/plus/provider/openssl/OpenSSLException"
    static const char *exceptionClass = EXCEPTION_CLASS;
#ifdef __MVS__
#pragma convert("ISO8859-1")
    static const char *exceptionClass_local = EXCEPTION_CLASS;
#pragma convert(pop)
#else
    static const char *exceptionClass_local = EXCEPTION_CLASS;
#endif

    jclass    clazz   = NULL;
    jstring   str     = NULL;
    jmethodID mid;
    jobject   obj     = NULL;
    char     *msgCopy = NULL;

    /* return immediately if an exception is already pending */
    if ((*env)->ExceptionCheck(env)) {
        return;
    }

    if (debug) {
        gslogMessage("Throwing exception %s : code=%d, msg=\"%s\"",
                     exceptionClass, code, (msg ? msg : ""));
    }

    if (!(clazz = (*env)->FindClass(env, exceptionClass_local))) {
        gslogError("Can't find class %s", exceptionClass_local);
        return;
    }

#ifdef __MVS__
    /* z/OS requires a mutable copy for __etoa (EBCDIC -> ASCII). */
    msgCopy = (char *)malloc(strlen(msg ? msg : "") + 1);
    if (msgCopy) {
        strcpy(msgCopy, msg ? msg : "");
        int rc = __etoa(msgCopy);
        if (rc < 1) {
            gslogError("_etoa failed in %s", __FUNCTION__);
        }
    } else {
        gslogError("malloc for msg failed.");
    }
#endif

    if (msg) {
        if (!(str = (*env)->NewStringUTF(env, msgCopy ? msgCopy : msg))) {
            gslogError("Can't create message string for exception");
            FREE_N_NULL(msgCopy);
            goto cleanup;
        }
        FREE_N_NULL(msgCopy);

#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
        mid = (*env)->GetMethodID(env, clazz, "<init>", "(Ljava/lang/String;)V");
#ifdef __MVS__
#pragma convert(pop)
#endif
        if (!mid) {
            gslogError("Can't find constructor for %s", exceptionClass);
            goto cleanup;
        }

        if (!(obj = (*env)->NewObject(env, clazz, mid, str))) {
            gslogError("Can't create exception object");
            goto cleanup;
        }
    } else {
#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
        if (!(mid = (*env)->GetMethodID(env, clazz, "<init>", "(I)V"))) {
#ifdef __MVS__
#pragma convert(pop)
#endif
            gslogError("Can't find default constructor for %s(int)",
                       exceptionClass);
            goto cleanup;
        }

        if (!(obj = (*env)->NewObject(env, clazz, mid, (jint)code))) {
            gslogError("Can't create exception object");
            goto cleanup;
        }
    }

    if ((*env)->Throw(env, obj) < 0) {
        gslogError("Can't throw %s", exceptionClass);
    }

cleanup:
    if (obj != NULL) {
        (*env)->DeleteLocalRef(env, obj);
    }
    if (str != NULL) {
        (*env)->DeleteLocalRef(env, str);
    }
    if (clazz != NULL) {
        (*env)->DeleteLocalRef(env, clazz);
    }
}

//============================================================================
// String helpers
//============================================================================

const char *getStringUTFCharsSafe(JNIEnv *env, jstring javaString,
                                  const char *errorMsg) {
    const char *str = (*env)->GetStringUTFChars(env, javaString, NULL);
    if (str == NULL) {
        throwOSSLException(env, 0, errorMsg);
    }
    return str;
}

void releaseStringUTFChars(JNIEnv *env, jstring javaString, const char *str) {
    if (str != NULL && javaString != NULL) {
        (*env)->ReleaseStringUTFChars(env, javaString, str);
    }
}

//============================================================================
// Byte array helpers
//============================================================================

jbyte *getByteArrayElementsSafe(JNIEnv *env, jbyteArray array,
                                const char *errorMsg) {
    jbyte *bytes = (*env)->GetByteArrayElements(env, array, NULL);
    if (bytes == NULL) {
        throwOSSLException(env, 0, errorMsg);
    }
    return bytes;
}

void releaseByteArrayElements(JNIEnv *env, jbyteArray array, jbyte *bytes,
                              jint mode) {
    if (bytes != NULL && array != NULL) {
        (*env)->ReleaseByteArrayElements(env, array, bytes, mode);
    }
}

//============================================================================
// Memory helpers
//============================================================================

void *mallocSafe(JNIEnv *env, size_t size, const char *errorMsg) {
    void *ptr = malloc(size);
    if (ptr == NULL) {
        throwOSSLException(env, 0, errorMsg);
        return NULL;
    }
    memset(ptr, 0, size);
    return ptr;
}

#ifdef __MVS__
#include "closed_Utils_c.h"
#endif
