/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

public interface AsymmetricKey {

    public String getAlgorithm();

    public long getPKeyId() throws OCKException;

    public byte[] getPrivateKeyBytes() throws OCKException;

    public byte[] getPublicKeyBytes() throws OCKException;
}
