/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.NativeCryptoSelector;
import com.ibm.crypto.plus.provider.base.NativeInterface;
import com.ibm.crypto.plus.provider.base.OJPKey;

final class KeyUtils {

    private KeyUtils() {
    }

    /**
     * Returns {@code true} if the given {@link OJPKey}'s backend matches the
     * backend that {@code provider} would select for {@code paramSetName} under
     * {@code serviceType}. Falls back to {@code false} on any error so translation
     * is attempted rather than silently skipped.
     */
    static boolean keyMatchesProvider(OpenJCEPlusProvider provider, String serviceType,
            OJPKey key, String paramSetName) {
        try {
            NativeInterface expected = NativeCryptoSelector.selectBackend(
                    provider, serviceType, paramSetName);
            NativeInterface actual = key.getBackendInterface();
            return expected.getBackendType() == actual.getBackendType();
        } catch (Exception e) {
            return false;
        }
    }
}
