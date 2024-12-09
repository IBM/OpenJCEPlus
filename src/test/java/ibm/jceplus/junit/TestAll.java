/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit;

import org.junit.platform.suite.api.SelectClasses;
import org.junit.platform.suite.api.Suite;

@SelectClasses({
    ibm.jceplus.junit.openjceplus.TestAll.class,
    ibm.jceplus.junit.openjceplusfips.TestAll.class
})

@Suite
public class TestAll {
}
