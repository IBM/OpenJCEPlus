/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

/**
 * Enumeration of test tags used to categorize tests.
 */
public enum Tags {

    OPENJCEPLUS(TestProvider.OpenJCEPlus.getProviderName()),
    OPENJCEPLUS_OPENSSL(TestProvider.OpenJCEPlus_OpenSSL.getProviderName()),
    OPENJCEPLUS_OCK(TestProvider.OpenJCEPlus_OCK.getProviderName()),
    OPENJCEPLUS_FIPS(TestProvider.OpenJCEPlusFIPS.getProviderName()),
    MULTITHREAD("Multithread");

    // Constants for tag names (can be used in annotations where compiler couldn't use a runtime method)
    public static final String OPENJCEPLUS_NAME = TestProvider.OPENJCEPLUS_NAME;
    public static final String OPENJCEPLUS_OPENSSL_NAME = TestProvider.OPENJCEPLUS_OPENSSL_NAME;
    public static final String OPENJCEPLUS_OCK_NAME = TestProvider.OPENJCEPLUS_OCK_NAME;
    public static final String OPENJCEPLUS_FIPS_NAME = TestProvider.OPENJCEPLUS_FIPS_NAME;
    public static final String MULTITHREAD_NAME = "Multithread";

    private final String tag;

    Tags(String tag) {
        this.tag = tag;
    }

    /**
     * Gets the tag value.
     *
     * @return the tag value
     */
    public String getTag() {
        return tag;
    }
}
