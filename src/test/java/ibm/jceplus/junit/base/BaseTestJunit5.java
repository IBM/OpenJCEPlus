/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;
abstract public class BaseTestJunit5 {

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
}
