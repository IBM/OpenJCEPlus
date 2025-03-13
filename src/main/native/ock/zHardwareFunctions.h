/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
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
