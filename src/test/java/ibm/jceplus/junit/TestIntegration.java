/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@SelectClasses({
    ibm.jceplus.junit.openjceplus.integration.TestAll.class,
    ibm.jceplus.junit.openjceplusfips.integration.TestAll.class
})

@Suite
public class TestIntegration {
}
