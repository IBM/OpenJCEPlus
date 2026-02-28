/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _RSAPADDING_H
#define _RSAPADDING_H

// NOTE: These constants must match those defined in
//       com.ibm.crypto.plus.provider.base.RSAPadding
//
#define RSAPAD_NONE 0
#define RSAPAD_PKCS1 1
#define RSAPAD_OAEP 2

#define NONE 0
#define SHA1 1
#define SHA224 2
#define SHA256 3
#define SHA384 4
#define SHA512 5
#define SHA512_224 6
#define SHA512_256 7

#endif
