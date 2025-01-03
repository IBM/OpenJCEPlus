/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef _RsaPss_H
#define _RsaPss_H

#include <jcc_a.h>
#include <icc.h>
#include "Digest.h"

#define EVP_PKEY_OP_SIGN (1 << 3)
#define EVP_PKEY_OP_VERIFY (1 << 4)
typedef struct OCKRsaPss {
    OCKDigest        *ockDigest;
    OCKDigest        *ockMGF1Digest;
    ICC_EVP_PKEY_CTX *evpPkeyCtx;
    ICC_EVP_PKEY     *ockPKey;
} OCKRsaPss;

#endif
