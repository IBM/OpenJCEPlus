/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKContext;
import java.lang.ref.Cleaner;
import java.security.ProviderException;
import java.util.concurrent.atomic.AtomicInteger;
import sun.security.util.Debug;

// Internal interface for OpenJCEPlus and OpenJCEPlus implementation classes.
// Implemented as an abstract class rather than an interface so that 
// methods can be package protected, as interfaces have only public methods.
// Code is not implemented in this class to ensure that any thread call
// stacks show it originating in the specific provider class.
//
public abstract class OpenJCEPlusProvider extends java.security.Provider {
    private static final long serialVersionUID = 1L;

    private static final String PROVIDER_VER = System.getProperty("java.specification.version");

    private static final String JAVA_VER = System.getProperty("java.specification.version");

    static final String DEBUG_VALUE = "jceplus";

    private final Cleaner[] cleaners;

    private final int DEFAULT_NUM_CLEANERS = 2;

    private final int numCleaners;

    private AtomicInteger count = new AtomicInteger(0);

    protected static final Debug debug = Debug.getInstance(DEBUG_VALUE); 

    OpenJCEPlusProvider(String name, String info) {
        super(name, PROVIDER_VER, info);

        numCleaners = Integer.getInteger("openjceplus.cleaners.num", DEFAULT_NUM_CLEANERS);
        if (numCleaners < 1){
            throw new IllegalArgumentException(numCleaners + " is an invalid number of cleaner threads, must be at least 1.");
        }

        cleaners = new Cleaner[numCleaners];
        for (int i = 0; i < numCleaners; i++) {
            final Cleaner cleaner = Cleaner.create();
            cleaners[i] = cleaner;
        }
    }

    /**
     * Any primitive instance variable whose value is changed after calling registerCleanable()
     * in the constructor must be changed to the PrimitiveWrapper type if the variable is passed
     * as a parameter to the Runnable cleaning method. This is to ensure the variable is passed by
     * reference instead of by value.
     */
    public void registerCleanable(Object owner, Runnable cleanAction) {
        Cleaner cleaner = cleaners[Math.abs(count.getAndIncrement() % numCleaners)];
        cleaner.register(owner, cleanAction);
    }

    public static Debug getDebug() {
        return debug;
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

    // Return the Java version.
    //
    String getJavaVersionStr() {
        return JAVA_VER;
    }

    abstract ProviderException providerException(String message, Throwable ockException);

    void setOCKExceptionCause(Exception exception, Throwable ockException) {
        if ((debug != null) && (exception != null) && (exception.getCause() == null)) {
            exception.initCause(ockException);
        }
    }
}
