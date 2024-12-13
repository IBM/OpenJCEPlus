/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
