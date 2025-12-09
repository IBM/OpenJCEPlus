/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.Provider;

abstract public class BaseTest {

    private String providerName;

    private int keysize = -1;

    private String algo = null;

    /**
     * Sets the provider name that is to be used to execute this test.
     * 
     * @param providerName the provider name associated with this test case for use.
     */
    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }

    public void setAndInsertProvider(TestProvider provider) throws Exception {
        this.providerName = provider.getProviderName();
        switch (provider) {
            case BC:
                loadProvider(TestProvider.BC);
                break;
            case SUN:
                loadProvider(TestProvider.SUN);
                break;
            case SunJCE:
                loadProvider(TestProvider.SunJCE);
                break;
            case SunRsaSign:
                loadProvider(TestProvider.SunRsaSign);
                break;
            case SunEC:
                loadProvider(TestProvider.SunEC);
                break;
            case OpenJCEPlus:
                loadProvider(TestProvider.OpenJCEPlus);
                break;
            case OpenJCEPlusFIPS:
                loadProvider(TestProvider.OpenJCEPlusFIPS);
                break;
            default:
                throw new Exception("Provider not supported: " + provider.getProviderName());
        }
    }

    private static Provider loadProvider(TestProvider testProvider) throws Exception {
        String providerName = testProvider.getProviderName();
        String providerClassName = testProvider.getProviderClassName();
        
        Provider provider = java.security.Security.getProvider(providerName);
        if (provider == null) {
            provider = (Provider) Class.forName(providerClassName).getDeclaredConstructor().newInstance();
            java.security.Security.insertProviderAt(provider, 0);
        }

        return provider;
    }

    /**
     * Gets the provider name that is to be used to execute this test.
     * 
     * @return The provider name associated with this test case for use.
     */
    public String getProviderName() {
        if (this.providerName == null) {
            throw new RuntimeException("Provider name is null.");
        }
        return this.providerName;
    }

    /**
     * Sets the algorithm associated with this test.
     * @param algorithm
     */
    public void setAlgorithm(String algorithm) {
        this.algo = algorithm;
    }

    /**
     * Gets the algorithm associated with this test.
     * @return
     */
    public String getAlgorithm() {
        if (this.algo == null) {
            throw new RuntimeException("Algorithm name is null.");
        }
        return this.algo;
    }

    /**
     * Sets the key size associated with this test.
     * @param keySize
     */
    public void setKeySize(int keySize) {
        this.keysize = keySize;
    }

    /**
     * Gets the key size associated with this test.
     * @return
     */
    public int getKeySize() {
        if (this.keysize == -1) {
            throw new RuntimeException("Key size is not correct.");
        }
        return this.keysize;
    }

    /**
     * Returns the tags from the -Dgroups system property.
     * If no groups property is set, returns an empty array.
     * @return String array of tag names from the groups property
     */
    public static String[] getTagsPropertyAsArray() {
        String groupsProperty = System.getProperty("groups");
        if (groupsProperty != null && !groupsProperty.trim().isEmpty()) {
            // Parse the comma-delimited list of groups and return as array
            String[] groups = groupsProperty.split(",");
            String[] trimmedGroups = new String[groups.length];
            for (int i = 0; i < groups.length; i++) {
                trimmedGroups[i] = groups[i].trim();
            }
            return trimmedGroups;
        } else {
            // If no -Dgroups specified, return empty
            return new String[0];
        }
    }
}
