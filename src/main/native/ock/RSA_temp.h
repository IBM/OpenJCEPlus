/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

/* This is a temporary file.
 * All these macros will be added to the next OCK release,
 * at which point this file must be removed.
 */
#define ICC_EVP_PKEY_CTRL_RSA_KEYGEN_BITS   (ICC_EVP_PKEY_ALG_CTRL + 3)
#define ICC_EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP (ICC_EVP_PKEY_ALG_CTRL + 4)
#define ICC_EVP_PKEY_CTRL_RSA_OAEP_MD       (ICC_EVP_PKEY_ALG_CTRL + 9)
#define ICC_EVP_PKEY_CTRL_RSA_OAEP_LABEL    (ICC_EVP_PKEY_ALG_CTRL + 10)
#define ICC_EVP_PKEY_CTRL_GET_RSA_OAEP_MD   (ICC_EVP_PKEY_ALG_CTRL + 11)
#define ICC_EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL (ICC_EVP_PKEY_ALG_CTRL + 12)
#define ICC_EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES  (ICC_EVP_PKEY_ALG_CTRL + 13)

/* copies of OpenSSL's helper function macros */

#define ICC_EVP_PKEY_RSA_PSS NID_rsassaPss

#define ICC_EVP_PKEY_OP_UNDEFINED           0
#define ICC_EVP_PKEY_OP_PARAMGEN            (1<<1)
#define ICC_EVP_PKEY_OP_KEYGEN              (1<<2)
#define ICC_EVP_PKEY_OP_SIGN                (1<<3)
#define ICC_EVP_PKEY_OP_VERIFY              (1<<4)
#define ICC_EVP_PKEY_OP_VERIFYRECOVER       (1<<5)
#define ICC_EVP_PKEY_OP_SIGNCTX             (1<<6)
#define ICC_EVP_PKEY_OP_VERIFYCTX           (1<<7)
#define ICC_EVP_PKEY_OP_ENCRYPT             (1<<8)
#define ICC_EVP_PKEY_OP_DECRYPT             (1<<9)
#define ICC_EVP_PKEY_OP_DERIVE              (1<<10)

#define ICC_EVP_PKEY_OP_TYPE_SIG    \
        (ICC_EVP_PKEY_OP_SIGN | ICC_EVP_PKEY_OP_VERIFY | ICC_EVP_PKEY_OP_VERIFYRECOVER \
                | ICC_EVP_PKEY_OP_SIGNCTX | ICC_EVP_PKEY_OP_VERIFYCTX)
#define ICC_EVP_PKEY_OP_TYPE_CRYPT \
        (ICC_EVP_PKEY_OP_ENCRYPT | ICC_EVP_PKEY_OP_DECRYPT)

#define ICC_EVP_PKEY_CTRL_MD                1
#define ICC_EVP_PKEY_CTRL_GET_MD            13


#define ICC_EVP_PKEY_CTX_set_rsa_padding(ctx, pctx, pad) \
        ICC_EVP_PKEY_CTX_ctrl(ctx,pctx,-1, -1, ICC_EVP_PKEY_CTRL_RSA_PADDING, pad, NULL)

#define ICC_EVP_PKEY_CTX_get_rsa_padding(ctx, pctx, ppad) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, -1, -1, ICC_EVP_PKEY_CTRL_GET_RSA_PADDING, 0, ppad)

#define ICC_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, pctx, len) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx,-1, (ICC_EVP_PKEY_OP_SIGN|ICC_EVP_PKEY_OP_VERIFY), ICC_EVP_PKEY_CTRL_RSA_PSS_SALTLEN,len, NULL)

#define ICC_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, pctx, len) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA_PSS, ICC_EVP_PKEY_OP_KEYGEN, \
                          ICC_EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)

#define ICC_EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, pctx, plen) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA_PSS, (ICC_EVP_PKEY_OP_SIGN|ICC_EVP_PKEY_OP_VERIFY), \
                          ICC_EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, plen)

#define ICC_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, pctx, bits) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_KEYGEN, \
                          ICC_EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL)

#define ICC_EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pctx, pubexp) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_KEYGEN, \
                          ICC_EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp)

#define ICC_EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, pctx, primes) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_KEYGEN, \
                          ICC_EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, primes, NULL)

#define  ICC_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, pctx, md) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_TYPE_SIG | ICC_EVP_PKEY_OP_TYPE_CRYPT, \
                          ICC_EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))

#define  ICC_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, pctx, md) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA_PSS, ICC_EVP_PKEY_OP_KEYGEN, \
                          ICC_EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))

#define  ICC_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, pctx, md) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_TYPE_CRYPT,  \
                          ICC_EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)(md))

#define  ICC_EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pctx, pmd) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_TYPE_SIG | ICC_EVP_PKEY_OP_TYPE_CRYPT, \
                          ICC_EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, (void *)(pmd))

#define  ICC_EVP_PKEY_CTX_get_rsa_oaep_md(ctx, pctx, pmd) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_TYPE_CRYPT,  \
                          ICC_EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, (void *)(pmd))

#define  ICC_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, pctx, l, llen) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_TYPE_CRYPT,  \
                          ICC_EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)(l))

#define  ICC_EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, pctx, l) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA, ICC_EVP_PKEY_OP_TYPE_CRYPT,  \
                          ICC_EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, (void *)(l))

#define  ICC_EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, pctx, md) \
        ICC_EVP_PKEY_CTX_ctrl(ctx, pctx, ICC_EVP_PKEY_RSA_PSS,  \
                          ICC_EVP_PKEY_OP_KEYGEN, ICC_EVP_PKEY_CTRL_MD,  \
                          0, (void *)(md))

