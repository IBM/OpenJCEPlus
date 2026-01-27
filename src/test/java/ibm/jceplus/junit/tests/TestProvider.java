/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

/**
 * Enumeration of security providers used through our various tests.
 */
public enum TestProvider {
    BC("BC", "org.bouncycastle.jce.provider.BouncyCastleProvider"),
    SUN("SUN", null),
    SunJCE("SunJCE", null),
    SunRsaSign("SunRsaSign", null),
    SunEC("SunEC", null),
    OpenJCEPlus("OpenJCEPlus", "com.ibm.crypto.plus.provider.OpenJCEPlus"),
    OpenJCEPlusFIPS("OpenJCEPlusFIPS", "com.ibm.crypto.plus.provider.OpenJCEPlusFIPS");

    // Constants for provider names (can be used in annotations where compiler couldn't use a runtime method)
    public static final String BC_NAME = "BC";
    public static final String SUN_NAME = "SUN";
    public static final String SUNJCE_NAME = "SunJCE";
    public static final String SUNRSASIGN_NAME = "SunRsaSign";
    public static final String SUNEC_NAME = "SunEC";
    public static final String OPENJCEPLUS_NAME = "OpenJCEPlus";
    public static final String OPENJCEPLUS_FIPS_NAME = "OpenJCEPlusFIPS";    

    private final String providerName;
    private final String providerClassName;

    TestProvider(String providerName, String providerClassName) {
        this.providerName = providerName;
        this.providerClassName = providerClassName;
    }

    /**
     * Gets the provider name.
     * 
     * @return the provider name
     */
    public String getProviderName() {
        return providerName;
    }

    /**
     * Gets the provider class name.
     * 
     * @return the provider class name, or null
     */
    public String getProviderClassName() {
        return providerClassName;
    }
}
