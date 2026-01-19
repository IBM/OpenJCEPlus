/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _UTILS_H
#define _UTILS_H

#include <jcc_a.h>
#include <icc.h>
#include <jni.h>

#define DIGEST_INTERNAL_SUCCESS 0
#define FAIL_DIGEST_FINAL -1
#define FAIL_DIGEST_INIT -2
#define FAIL_DIGEST_UPDATE -3

#define CIPHER_INTERNAL_SUCCESS 0
#define FAIL_CIPHER_INTERNAL_ENCRYPTUPDATE -1
#define FAIL_CIPHER_INTERNAL_ENCRYPTFINAL -2
#define FAIL_CIPHER_INTERNAL_DECRYPTUPDATE -3
#define FAIL_CIPHER_INTERNAL_DECRYPTFINAL -4
#define FAIL_CIPHER_INTERNAL_DECRYPTFINAL_BAD_PADDING_ERROR -5

#define HMAC_INTERNAL_SUCCESS 0
#define FAIL_HMAC_INTERNAL_INIT -1
#define FAIL_HMAC_INTERNAL_UPDATE -2
#define FAIL_HMAC_INTERNAL_DOFINAL -3

#define FREE_N_NULL(_ptr) \
    if ((_ptr) != NULL) { \
        free((_ptr));     \
        (_ptr) = NULL;    \
    }

extern int debug;

void com_ibm_crypto_plus_provider_initialize(void);

int gslogFunctionEntry(const char* functionName);
int gslogError(const char* formatString, ...);
int gslogMessage(const char* formatString, ...);
int gslogMessagePrefix(const char* formatString, ...);
int gslogMessageHex(char byte[], int offset, int length, int spaceAfter,
                    int newlineAfter, char* newlinePrefix);
int gslogFunctionExit(const char* functionName);

void ockCheckStatus(ICC_CTX* ctx);

void throwOCKException(JNIEnv* env, int code, const char* msg);

#ifdef __MVS__
void forceToAscii(char* s);
#endif

#endif
