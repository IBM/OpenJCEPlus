/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.suites;

import ibm.jceplus.junit.tests.Tags;

/**
 * Multi-threaded test suite that runs all tests tagged with "OpenJCEPlusFIPSMultithread"
 * from the ibm.jceplus.junit.tests package.
 */
public class TestMultiThreadOpenJCEPlusFIPS extends BaseTestMultiThread {

    public TestMultiThreadOpenJCEPlusFIPS() {
        super();
    }

    @Override
    protected String getTagName() {
        return Tags.OPENJCEPLUS_FIPS_MULTITHREAD.getTag();
    }
}
