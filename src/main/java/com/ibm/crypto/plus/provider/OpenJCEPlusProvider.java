/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.ProviderException;
import com.ibm.crypto.plus.provider.ock.OCKContext;

// Internal interface for OpenJCEPlus and OpenJCEPlus implementation classes.
// Implemented as an abstract class rather than an interface so that 
// methods can be package protected, as interfaces have only public methods.
// Code is not implemented in this class to ensure that any thread call
// stacks show it originating in the specific provider class.
//
@SuppressWarnings({"serial", "removal", "deprecation"})
abstract class OpenJCEPlusProvider extends java.security.Provider {
    private static final String PROVIDER_VER = java.security.AccessController
                .doPrivileged(new java.security.PrivilegedAction<String>() {
                    public String run() {
                        return (System.getProperty("java.specification.version"));
                    }
                });

    // Are we debugging? -- for developers
    static final boolean debug2 = false;

    //    private static boolean verifiedSelfIntegrity = false;
    private static boolean verifiedSelfIntegrity = true;

    OpenJCEPlusProvider(String name, String info) {
        super(name, PROVIDER_VER, info);
    }

    static final boolean verifySelfIntegrity(Class c) {
        if (verifiedSelfIntegrity) {
            return true;
        }

        return doSelfVerification(c);
    }

    private static final synchronized boolean doSelfVerification(Class c) {
        return true;
    }

    // Get OCK context for crypto operations
    //
    abstract OCKContext getOCKContext();

    // Get the context associated with the provider. The context is used in
    // serialization to be able to keep track of the associated provider.
    //
    abstract ProviderContext getProviderContext();

    // Get SecureRandom to use for crypto operations. If in FIPS mode, returns a
    // FIPS
    // approved SecureRandom to use.
    //
    abstract java.security.SecureRandom getSecureRandom(
            java.security.SecureRandom userSecureRandom);

    // Return whether the provider is FIPS. If the provider is using an OCK
    // context in FIPS mode then it is FIPS.
    //
    boolean isFIPS() {
        return getOCKContext().isFIPS();
    }

    abstract ProviderException providerException(String message, Throwable ockException);

    abstract void setOCKExceptionCause(Exception exception, Throwable ockException);
}
