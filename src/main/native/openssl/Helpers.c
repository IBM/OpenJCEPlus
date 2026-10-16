/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include "Helpers.h"

//============================================================================
// Exception helpers
//============================================================================

void throwNPE(JNIEnv *env, const char *msg) {
    jclass cls = (*env)->FindClass(env, "java/lang/NullPointerException");
    if (cls != NULL) (*env)->ThrowNew(env, cls, msg);
}

void throwOOM(JNIEnv *env, const char *msg) {
    jclass cls = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
    if (cls != NULL) (*env)->ThrowNew(env, cls, msg);
}

void throwISE(JNIEnv *env, const char *msg) {
    jclass cls = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (cls != NULL) (*env)->ThrowNew(env, cls, msg);
}

//============================================================================
// String helpers
//============================================================================

const char *getStringUTFCharsSafe(JNIEnv *env, jstring javaString,
                                  const char *errorMsg) {
    const char *str = (*env)->GetStringUTFChars(env, javaString, NULL);
    if (str == NULL) {
        throwOOM(env, errorMsg);
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
        throwOOM(env, errorMsg);
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
        setPendingOpenSSLException(env, OPENSSL_ALLOCATION_FAILED, errorMsg);
        return NULL;
    }
    memset(ptr, 0, size);
    return ptr;
}
