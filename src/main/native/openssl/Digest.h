/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _DIGEST_H
#define _DIGEST_H

#include <openssl/evp.h>

typedef struct OSSLDigest {
    EVP_MD_CTX*   mdCtx;
    const EVP_MD* md;
} OSSLDigest;

#endif
