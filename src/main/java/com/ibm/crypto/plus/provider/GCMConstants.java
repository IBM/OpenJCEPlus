/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

/**
 * Interface for GCM constants.
 */
interface GCMConstants {

    /* Generated IV maximum number of invocations */
    public static final String GENERATED_IV_MAX_INVOCATIONS = "18446744073709551615";

    /* Generated IV fixed field length in bytes */
    public static final int GENERATED_IV_DEVICE_FIELD_LENGTH = 32 / 8;

    /* Generated IV invocation field length in bytes */
    public static final int GENERATED_IV_COUNTER_FIELD_LENGTH = 64 / 8;

    /* Generated IV total combined length in bytes */
    public static final int GENERATED_IV_TOTAL_LENGTH = GENERATED_IV_DEVICE_FIELD_LENGTH
            + GENERATED_IV_COUNTER_FIELD_LENGTH;

    public static final int DEFAULT_TAG_LENGTH = 128;

    public static final int[] GCM_TAG_LENGTHS = {128, 120, 112, 104, 96};

}
