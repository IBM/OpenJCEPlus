/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

typedef size_t UDATA;

typedef int (*PFI)(void);

typedef struct {
    char *name;
    PFI   func;
} FUNC;

// Function pointers for z specific hardware instructions.
typedef void (*ECB_FuncPtr)(signed char *, signed char *, UDATA *,
                            signed char *, UDATA *);
typedef void (*GHASH_FuncPtr)(signed char *, UDATA *, signed char *, UDATA *);
typedef void (*zS390_FuncPtr)(unsigned char *, unsigned char *, unsigned char *,
                              long *, long *, unsigned char *, long *);
typedef void (*KMC_FuncPtr)(unsigned char *, unsigned char *, UDATA *, long,
                            UDATA *);
