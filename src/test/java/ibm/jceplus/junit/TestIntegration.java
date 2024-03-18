/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@Suite
@SelectClasses({ibm.jceplus.junit.openjceplus.integration.TestAll.class,
                ibm.jceplus.junit.openjceplusfips.integration.TestAll.class})
public class TestIntegration {
    
}
