/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

public class BaseTestInterop extends BaseTest {

    public String interopProviderName;
    public String interopProviderName2;

    /**
     * Sets the provider name to interop with.
     *
     * @param providerName the provider name associated with this test case for use.
     */
    public void setInteropProviderName(String providerName) {
        this.interopProviderName = providerName;
    }

    /**
     * Sets the interop provider name and loads the provider.
     *
     * @param interopProvider the provider to be used for interop.
     */
    public void setAndInsertInteropProvider(TestProvider interopProvider) throws Exception {
        this.interopProviderName = interopProvider.getProviderName();
        loadSupportedProvider(interopProvider);
    }

    /**
     * Gets the provider name that is to be used for interop.
     *
     * @return The provider name associated with the interop provider name.
     */
    public String getInteropProviderName() {
        return this.interopProviderName;
    }

    /**
     * Sets the provider name to interop with.
     *
     * @param providerName the provider name associated with this test case for use.
     */
    public void setInteropProviderName2(String providerName) {
        this.interopProviderName2 = providerName;
    }

    /**
     * Gets the provider name that is to be used for interop.
     *
     * @return The provider name associated with the interop provider name.
     */
    public String getInteropProviderName2() {
        return this.interopProviderName2;
    }
}
