/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.suites;

import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;

/**
 * Test suite that executes all tests in the ibm.jceplus.junit.tests package.
 * This suite runs all tests regardless of tags.
 */
@Suite
@SelectPackages("ibm.jceplus.junit.tests")
public class TestAll {
}
