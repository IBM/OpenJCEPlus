/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

public interface AsymmetricKey {

    public String getAlgorithm();

    public long getPKeyId() throws OCKException;

    public byte[] getPrivateKeyBytes() throws OCKException;

    public byte[] getPublicKeyBytes() throws OCKException;
}
