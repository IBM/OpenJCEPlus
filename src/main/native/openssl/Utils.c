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
#include <openssl/evp.h>
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

//============================================================================
//
// DER OctetString helpers
//
unsigned char *encode_octet_string(const unsigned char *raw, size_t rawLen, size_t *outLen) {
    if (rawLen > 0xFFFF) {
        return NULL;
    }
    *outLen = rawLen + 4;
    unsigned char *buf = (unsigned char *)malloc(*outLen);
    if (buf == NULL) {
        return NULL;
    }
    buf[0] = 0x04;  /* OctetString tag */
    buf[1] = 0x82;  /* long-form length, 2 bytes follow */
    buf[2] = (unsigned char)((rawLen >> 8) & 0xFF);
    buf[3] = (unsigned char)(rawLen & 0xFF);
    memcpy(buf + 4, raw, rawLen);
    return buf;
}

unsigned char *decode_octet_string(const unsigned char *enc, size_t encLen, size_t *rawLen) {
    if (encLen < 4 || enc[0] != 0x04 || enc[1] != 0x82) {
        return NULL;
    }
    *rawLen = ((size_t)(enc[2]) << 8) | (size_t)(enc[3]);
    if (*rawLen + 4 != encLen) {
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc(*rawLen);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, enc + 4, *rawLen);
    return buf;
}

//============================================================================
//
// DER BitString helpers
//
unsigned char *encode_bit_string(const unsigned char *raw, size_t rawLen, size_t *outLen) {
    /* BitString payload = 0x00 (unused bits) + raw */
    size_t payload = rawLen + 1;
    if (payload > 0xFFFF) {
        return NULL;
    }
    *outLen = payload + 4; /* tag + 0x82 + 2 length bytes + payload */
    unsigned char *buf = (unsigned char *)malloc(*outLen);
    if (buf == NULL) {
        return NULL;
    }
    buf[0] = 0x03;  /* BitString tag */
    buf[1] = 0x82;  /* long-form length, 2 bytes follow */
    buf[2] = (unsigned char)((payload >> 8) & 0xFF);
    buf[3] = (unsigned char)(payload & 0xFF);
    buf[4] = 0x00;  /* unused bits = 0 */
    memcpy(buf + 5, raw, rawLen);
    return buf;
}

unsigned char *decode_bit_string(const unsigned char *enc, size_t encLen, size_t *rawLen) {
    if (encLen < 5 || enc[0] != 0x03 || enc[1] != 0x82) {
        return NULL;
    }
    size_t payload = ((size_t)(enc[2]) << 8) | (size_t)(enc[3]);
    if (payload < 1 || payload + 4 != encLen || enc[4] != 0x00) {
        return NULL;
    }
    *rawLen = payload - 1;
    unsigned char *buf = (unsigned char *)malloc(*rawLen);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, enc + 5, *rawLen);
    return buf;
}

#ifdef __MVS__
#include "closed_Utils_c.h"
#endif
