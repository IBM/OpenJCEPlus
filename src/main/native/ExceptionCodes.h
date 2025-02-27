/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#ifndef _EXCEPTION_CODES_H
#define _EXCEPTION_CODES_H

// NOTE: These constants must match those defined in
//       com.ibm.crypto.plus.provider.ock.OCKException
//
#define GKR_FIPS_MODE_INVALID 0x00000001
#define GKR_OCK_ATTACH_FAILED 0x00000002
#define GKR_DECRYPT_FINAL_BAD_PADDING_ERROR 0x00000003
#define GKR_UNSPECIFIED 0x80000000;

#endif
