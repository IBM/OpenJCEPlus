/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLContext.h
 * @brief OpenSSL library context structure and constants.
 *
 * This header defines the OpenSSL context structure and constants used
 * throughout the native code. The context manages OpenSSL library contexts
 * and providers.
 *
 * In OpenSSL 3.0+, library contexts (OSSL_LIB_CTX) provide isolation
 * between different configurations, and providers supply cryptographic
 * algorithm implementations.
 */

#ifndef _OPENSSL_CONTEXT_H
#define _OPENSSL_CONTEXT_H

#include <jni.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/**
 * @defgroup Context_Constants Context Query Constants
 * These constants must match those defined in
 * com.ibm.crypto.plus.provider.openssl.OpenSSLContext
 * @{
 */

/** Query constant for FIPS approved mode status (always 0/false) */
#define VALUE_FIPS_APPROVED_MODE 0

/** Query constant for OpenSSL installation path */
#define VALUE_OPENSSL_INSTALL_PATH 1

/** Query constant for OpenSSL version string */
#define VALUE_OPENSSL_VERSION 2

/** @} */  // end of Context_Constants

/**
 * @struct OpenSSLContext
 * @brief OpenSSL library context structure.
 *
 * Maintains the state for an OpenSSL library context including
 * the library context itself and loaded providers.
 */
typedef struct {
    jlong          id;          /**< Unique context identifier */
    OSSL_LIB_CTX*  libctx;      /**< OpenSSL library context */
    OSSL_PROVIDER* fips;        /**< FIPS provider (unused, reserved) */
    OSSL_PROVIDER* base;        /**< Base provider (encoders, decoders) */
    OSSL_PROVIDER* defaultProv; /**< Default provider (full algorithm suite) */
} OpenSSLContext;

#endif
