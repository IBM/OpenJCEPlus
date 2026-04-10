/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import com.ibm.crypto.plus.provider.base.OCKException;

public final class OCKContext {

    private long ockContextId;
    private boolean isFIPS;

    public static OCKContext createContext(long ockContextId, boolean isFIPS) throws OCKException {

        return new OCKContext(ockContextId, isFIPS);
    }

    private OCKContext(long ockContextId, boolean isFIPS) {
        this.ockContextId = ockContextId;
        this.isFIPS = isFIPS;
    }

    public long getId() {
        return ockContextId;
    }

    public boolean isFIPS() {
        return isFIPS;
    }

    public String toString() {
        return "OCKContext [isFIPS=" + isFIPS + ", id=" + ockContextId + "]";
    }
}
