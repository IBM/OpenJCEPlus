/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
