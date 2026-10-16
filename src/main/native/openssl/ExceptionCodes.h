/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/**
 * @file ExceptionCodes.h
 * @brief Error codes for OpenSSL JNI exceptions.
 *
 * This header defines error codes used when throwing OpenSSLException
 * from native code to Java. Each code corresponds to a specific error
 * condition and helps Java code identify and handle errors appropriately.
 *
 * These constants must match those defined in
 * com.ibm.crypto.plus.provider.openssl.OpenSSLException
 */

#ifndef _OPENSSL_EXCEPTION_CODES_H
#define _OPENSSL_EXCEPTION_CODES_H

/* General errors */
#define OPENSSL_FIPS_MODE_INVALID          0x00000001
#define OPENSSL_LIBRARY_LOAD_FAILED        0x00000002
#define OPENSSL_PROVIDER_LOAD_FAILED       0x00000003
#define OPENSSL_DIGEST_INIT_FAILED         0x00000004
#define OPENSSL_DIGEST_UPDATE_FAILED       0x00000005
#define OPENSSL_DIGEST_FINAL_FAILED        0x00000006

/* Digest errors */
#define OPENSSL_DIGEST_NULL                0x0000000F
#define OPENSSL_DIGEST_INVALID             0x00000010
#define OPENSSL_DIGEST_ALGORITHM_NOT_FOUND 0x00000011
#define OPENSSL_DIGEST_CTX_NEW_FAILED      0x00000012
#define OPENSSL_DIGEST_COPY_FAILED         0x00000013

/* Random (SecureRandom / DRBG) errors */
#define OPENSSL_RAND_GENERATE_FAILED       0x00000030
#define OPENSSL_RAND_FETCH_FAILED          0x00000031
#define OPENSSL_RAND_CTX_NEW_FAILED        0x00000032
#define OPENSSL_RAND_INSTANTIATE_FAILED    0x00000033
#define OPENSSL_RAND_RESEED_FAILED         0x00000034

/* Context / parameter errors */
#define OPENSSL_INVALID_PARAMETER          0x00000020
#define OPENSSL_ALLOCATION_FAILED          0x00000021

/* Unspecified / generic errors */
#define OPENSSL_UNSPECIFIED                0x80000000

#endif
