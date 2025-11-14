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
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "Utils.h"
#include <string.h>

static int initialized = 0;

int debug = 0;  // FIXME

//============================================================================
//
//
void com_ibm_crypto_plus_provider_initialize(void) {
    if (!initialized) {
#if DEBUG
        /*if( getenv("JICC.debug") != NULL ) {*/
        debug = 1;  // FIXME;
                    /*}*/
#endif
        initialized = 1;
    }
}

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
    static char printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsprintf(printBuffer, formatString, formatArgs);

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
    static char printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsprintf(printBuffer, formatString, formatArgs);

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
    static char printBuffer[4096];

    va_start(formatArgs, formatString);
    charsPrinted = vsprintf(printBuffer, formatString, formatArgs);

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
void ockCheckStatus(ICC_CTX *ctx) {
    if (debug) {
        unsigned long errCode;

        while ((errCode = ICC_ERR_get_error(ctx)) == 1) {
            char *err;
            // gslogMessage("Generating error message");
            err = ICC_ERR_error_string(ctx, errCode, NULL);
            gslogMessage("%s", err);
        }
    }
}

//============================================================================
//
//
void throwOCKException(JNIEnv *env, int code, const char *msg) {
#define EXCEPTION_CLASS "com/ibm/crypto/plus/provider/ock/OCKException"
    static const char *exceptionClass = EXCEPTION_CLASS;
#ifdef __MVS__
#pragma convert("ISO8859-1")
    static const char *exceptionClass_local = EXCEPTION_CLASS;
#pragma convert(pop)
#else
    static const char *exceptionClass_local = EXCEPTION_CLASS;
#endif

    jclass    clazz;
    jstring   str = NULL;
    jmethodID mid;
    jobject   obj     = NULL;
    char     *msgCopy = NULL;

    /* return immediately if an exception is already pending */
    if ((*env)->ExceptionOccurred(env)) {
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

    if (msg) {
        msgCopy = (char *)malloc(
            strlen(msg) + 1); /* for some reason strdup just throws segvs when
                                 used against msg, so brute force. */
        if (msgCopy) {
            strcpy(msgCopy, msg);
#ifdef __MVS__
            int rc = __etoa(msgCopy);
            if (rc < 1) {
                gslogError("_etoa failed in %s", __FUNCTION__);
            }
#endif
        } else {
            gslogError("malloc for msg failed.");
        }

        if (!(str = (*env)->NewStringUTF(env, msgCopy))) {
            gslogError("Can't create message string for exception");
            if (msgCopy) {
                free(msgCopy);
                msgCopy = NULL;
            }
            return;
        }
        FREE_N_NULL(msgCopy);

#ifdef __MVS__
#pragma convert("ISO8859-1")
#endif
        if (!(mid = (*env)->GetMethodID(env, clazz, "<init>",
                                        "(Ljava/lang/String;)V"))) {
#ifdef __MVS__
#pragma convert(pop)
#endif
            gslogError("Can't find constuctor(message) for %s", exceptionClass);
            return;
        }

        if (!(obj = (*env)->NewObject(env, clazz, mid, str))) {
            gslogError("Can't create exception object");
            return;
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
            return;
        }

        if (!(obj = (*env)->NewObject(env, clazz, mid, (jint)code))) {
            gslogError("Can't create exception object");
            return;
        }
    }

    if ((*env)->Throw(env, obj) < 0) {
        gslogError("Can't throw %s", exceptionClass);
    }
}

#ifdef __MVS__
#include "closed_Utils_c.h"
#endif
