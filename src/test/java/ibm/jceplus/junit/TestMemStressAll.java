/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit;

import junit.framework.JUnit4TestAdapter;
import junit.framework.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({ibm.jceplus.junit.openjceplus.memstress.TestMemStressAll.class,})

public class TestMemStressAll {

    /**
     * @param args
     */

    public static Test suite() {
        return new JUnit4TestAdapter(TestMemStressAll.class);
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }

}

