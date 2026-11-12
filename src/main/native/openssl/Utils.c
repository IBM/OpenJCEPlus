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
// DER helpers (shared by OctetString and BitString)
//
#define DER_TAG_BIT_STRING   0x03
#define DER_TAG_OCTET_STRING 0x04

/*
 * A BitString's content starts with an "unused bits" byte; an OctetString's
 * content is the raw bytes only.
 */
static size_t der_prefix_len(unsigned char tag) {
    return (tag == DER_TAG_BIT_STRING) ? 1 : 0;
}

/*
 * Encode raw bytes as a DER TLV with the given tag (BitString or OctetString).
 * For BitString, a leading unused-bits byte (0x00) is prepended to the content.
 * Only lengths up to 0xFFFF are supported.
 * Returns a malloc'd buffer (caller frees), or NULL on failure.
 */
static unsigned char *der_encode(unsigned char tag, const unsigned char *raw,
                                 size_t rawLen, size_t *outLen) {
    size_t prefixLen = der_prefix_len(tag);
    size_t payload = rawLen + prefixLen;
    if (payload > 0xFFFF) {
        return NULL;
    }
    size_t headerLen;
    if (payload <= 0x7F) {
        headerLen = 2;          /* tag + 1-byte short-form length */
    } else if (payload <= 0xFF) {
        headerLen = 3;          /* tag + 0x81 + 1 length byte */
    } else {
        headerLen = 4;          /* tag + 0x82 + 2 length bytes */
    }
    *outLen = payload + headerLen;
    unsigned char *buf = (unsigned char *)malloc(*outLen);
    if (buf == NULL) {
        return NULL;
    }
    buf[0] = tag;
    if (headerLen == 2) {
        buf[1] = (unsigned char)payload;
    } else if (headerLen == 3) {
        buf[1] = 0x81;
        buf[2] = (unsigned char)payload;
    } else {
        buf[1] = 0x82;
        buf[2] = (unsigned char)((payload >> 8) & 0xFF);
        buf[3] = (unsigned char)(payload & 0xFF);
    }
    if (prefixLen) {
        buf[headerLen] = 0x00;  /* unused bits = 0 */
    }
    memcpy(buf + headerLen + prefixLen, raw, rawLen);
    return buf;
}

/*
 * Decode a DER TLV with the given tag (BitString or OctetString).
 * For BitString, the leading unused-bits byte must be 0x00 and is skipped.
 * Returns a malloc'd buffer of the raw content (caller frees), or NULL on
 * failure.
 */
static unsigned char *der_decode(unsigned char tag, const unsigned char *enc,
                                 size_t encLen, size_t *rawLen) {
    size_t prefixLen = der_prefix_len(tag);
    if (encLen < 2 || enc[0] != tag) {
        return NULL;
    }
    size_t payload;
    size_t headerLen;
    if ((enc[1] & 0x80) == 0) {
        /* short-form: length fits in one byte */
        payload   = (size_t)(enc[1]);
        headerLen = 2;
    } else if (enc[1] == 0x81 && encLen >= 3) {
        /* long-form, 1 subsequent length byte */
        payload   = (size_t)(enc[2]);
        headerLen = 3;
    } else if (enc[1] == 0x82 && encLen >= 4) {
        /* long-form, 2 subsequent length bytes */
        payload   = ((size_t)(enc[2]) << 8) | (size_t)(enc[3]);
        headerLen = 4;
    } else {
        return NULL;
    }
    if (payload < prefixLen || payload + headerLen != encLen) {
        return NULL;
    }
    if (prefixLen && enc[headerLen] != 0x00) {
        return NULL;
    }
    *rawLen = payload - prefixLen;
    unsigned char *buf = (unsigned char *)malloc(*rawLen);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, enc + headerLen + prefixLen, *rawLen);
    return buf;
}

//============================================================================
//
// DER OctetString helpers
//
unsigned char *encode_octet_string(const unsigned char *raw, size_t rawLen, size_t *outLen) {
    return der_encode(DER_TAG_OCTET_STRING, raw, rawLen, outLen);
}

unsigned char *decode_octet_string(const unsigned char *enc, size_t encLen, size_t *rawLen) {
    return der_decode(DER_TAG_OCTET_STRING, enc, encLen, rawLen);
}

//============================================================================
//
// DER BitString helpers
//
unsigned char *encode_bit_string(const unsigned char *raw, size_t rawLen, size_t *outLen) {
    return der_encode(DER_TAG_BIT_STRING, raw, rawLen, outLen);
}

unsigned char *decode_bit_string(const unsigned char *enc, size_t encLen, size_t *rawLen) {
    return der_decode(DER_TAG_BIT_STRING, enc, encLen, rawLen);
}

#ifdef __MVS__
#include "closed_Utils_c.h"
#endif
