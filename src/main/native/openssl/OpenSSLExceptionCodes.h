/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file OpenSSLExceptionCodes.h
 * @brief Error codes for OpenSSL JNI exceptions.
 *
 * This header defines error codes used when throwing OpenSSLException
 * from native code to Java. Each code corresponds to a specific error
 * condition and helps Java code identify and handle errors appropriately.
 *
 * These constants must match those defined in
 * com.ibm.crypto.plus.provider.openssl.OpenSSLException
 *
 * Error code categories:
 * - 0x00000001-0x0000000E: General errors (FIPS, library, providers, ciphers)
 * - 0x0000000F-0x00000013: Digest-specific errors
 * - 0x0000001E-0x00000021: Context and parameter errors
 * - 0x80000000: Unspecified/generic errors
 *
 * Codes 0x00000014-0x00000034 are reserved for future algorithm support
 * (HMAC, KDF, signature, key pair generation, EC, RSA).
 */

#ifndef _OPENSSL_EXCEPTION_CODES_H
#define _OPENSSL_EXCEPTION_CODES_H

/**
 * @defgroup General_Errors General Error Codes
 * @{
 */

/** FIPS mode requested but not available or invalid */
#define OPENSSL_FIPS_MODE_INVALID 0x00000001

/** Failed to load OpenSSL library */
#define OPENSSL_LIBRARY_LOAD_FAILED 0x00000002

/** Failed to load OpenSSL provider (FIPS, base, or default) */
#define OPENSSL_PROVIDER_LOAD_FAILED 0x00000003

/** Failed to initialize digest operation */
#define OPENSSL_DIGEST_INIT_FAILED 0x00000004

/** Failed to update digest with data */
#define OPENSSL_DIGEST_UPDATE_FAILED 0x00000005

/** Failed to finalize digest operation */
#define OPENSSL_DIGEST_FINAL_FAILED 0x00000006

/** Failed to seed random number generator */
#define OPENSSL_RAND_SEED_FAILED 0x00000007

/** Failed to generate random bytes */
#define OPENSSL_RAND_BYTES_FAILED 0x00000008

/** Failed to initialize cipher operation */
#define OPENSSL_CIPHER_INIT_FAILED 0x00000009

/** Failed to update cipher with data */
#define OPENSSL_CIPHER_UPDATE_FAILED 0x0000000A

/** Failed to finalize cipher operation */
#define OPENSSL_CIPHER_FINAL_FAILED 0x0000000B

/** Authentication tag verification failed (GCM/CCM) */
#define OPENSSL_CIPHER_TAG_MISMATCH 0x0000000E

/** @} */  // end of General_Errors

/**
 * @defgroup Digest_Errors Digest-Specific Error Codes
 * @{
 */

/** Digest context is NULL */
#define OPENSSL_DIGEST_NULL 0x0000000F

/** Digest context is invalid or corrupted */
#define OPENSSL_DIGEST_INVALID 0x00000010

/** Requested digest algorithm not found */
#define OPENSSL_DIGEST_ALGORITHM_NOT_FOUND 0x00000011

/** Failed to create new digest context */
#define OPENSSL_DIGEST_CTX_NEW_FAILED 0x00000012

/** Failed to copy digest context */
#define OPENSSL_DIGEST_COPY_FAILED 0x00000013

/** @} */  // end of Digest_Errors

/**
 * @defgroup Context_Errors Context and Parameter Error Codes
 * @{
 */

/** Failed to initialize OpenSSL context */
#define OPENSSL_CONTEXT_INIT_FAILED 0x0000001E

/** OpenSSL context is NULL */
#define OPENSSL_CONTEXT_NULL 0x0000001F

/** Invalid parameter provided to function */
#define OPENSSL_INVALID_PARAMETER 0x00000020

/** Memory allocation failed */
#define OPENSSL_ALLOCATION_FAILED 0x00000021

/** @} */  // end of Context_Errors

/** Unspecified or generic error */
#define OPENSSL_UNSPECIFIED 0x80000000

#endif
