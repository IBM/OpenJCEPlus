/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.suites;

/**
 * Multi-threaded test suite that runs all tests tagged with "OpenJCEPlus"
 * from the ibm.jceplus.junit.tests package.
 */
public class TestMultiThreadOpenJCEPlus extends BaseTestMultiThread {

    public TestMultiThreadOpenJCEPlus() {
        super();
    }

    @Override
    protected String getTagName() {
        return "OpenJCEPlus";
    }
}
