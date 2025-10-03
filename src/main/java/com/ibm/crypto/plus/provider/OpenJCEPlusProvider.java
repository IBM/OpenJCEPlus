/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKContext;
import java.lang.ref.Cleaner;
import java.security.ProviderException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

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

    static final boolean allowLegacyHKDF = Boolean.getBoolean("openjceplus.allowLegacyHKDF");

    //    private static boolean verifiedSelfIntegrity = false;
    private static final boolean verifiedSelfIntegrity = true;

    private final Cleaner[] cleaners;

    private final int DEFAULT_NUM_CLEANERS = 2;

    private final int CUSTOM_NUM_CLEANERS;

    private AtomicInteger count = new AtomicInteger(0);

    OpenJCEPlusProvider(String name, String info) {
        super(name, PROVIDER_VER, info);

        int tempNumCleaners = DEFAULT_NUM_CLEANERS;
        String newNumCleaners = System.getProperty("numCleaners");
        if (newNumCleaners != null){
            try {
                int parsedValue = Integer.parseInt(newNumCleaners);

                if (parsedValue >= 1){
                    tempNumCleaners = parsedValue;
                }
                else {
                    System.err.println("Number of Cleaner threads must be set to atleast 1, defaulting to 2 Cleaners.");
                }
            }
            catch (NumberFormatException e) {
                System.err.println("Number of Cleaner threads must be an integer, defaulting to 2 Cleaners.");
            }
        }
        CUSTOM_NUM_CLEANERS = tempNumCleaners;

        cleaners = new Cleaner[CUSTOM_NUM_CLEANERS];
        for (int i = 0; i < CUSTOM_NUM_CLEANERS; i++) {
            final Cleaner cleaner = Cleaner.create(new CleanerThreadFactory());
            cleaners[i] = cleaner;
        }
    }

    static final boolean verifySelfIntegrity(Object c) {
        if (verifiedSelfIntegrity) {
            return true;
        }

        return doSelfVerification(c);
    }

    private static final synchronized boolean doSelfVerification(Object c) {
        return true;
    }

    public void registerCleanable(Object owner, Runnable cleanAction) {
        Cleaner cleaner = cleaners[count.getAndIncrement() % CUSTOM_NUM_CLEANERS];
        cleaner.register(owner, cleanAction);
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

    abstract void setOCKExceptionCause(Exception exception, Throwable ockException);

    private static class CleanerThreadFactory implements ThreadFactory {

        @Override
        public Thread newThread(Runnable r) {
            Thread thread = new Thread(r);
            thread.setPriority(Thread.MAX_PRIORITY);
            return thread;
        }

    }
}
