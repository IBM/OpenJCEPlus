/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
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
