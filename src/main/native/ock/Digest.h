/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _DIGEST_H
#define _DIGEST_H

#include <jcc_a.h>
#include <icc.h>

typedef struct OCKDigest {
    ICC_EVP_MD_CTX*   mdCtx;
    const ICC_EVP_MD* md;
} OCKDigest;

#endif
