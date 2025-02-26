/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

public class BaseTestJunit5Interop extends BaseTestJunit5 {

    public String interopProviderName;

    /**
     * Sets the provider name to interop with.
     * 
     * @param providerName the provider name associated with this test case for use.
     */
    public void setInteropProviderName(String providerName) {
        this.interopProviderName = providerName;
    }

    /**
     * Gets the provider name that is to be used for interop.
     * 
     * @return The provider name associated with the interop provider name.
     */
    public String getInteropProviderName() {
        return this.interopProviderName;
    }
}
