/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.openjceplusfips;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestChaCha20Poly1305ChunkUpdate
        extends ibm.jceplus.junit.base.BaseTestChaCha20Poly1305ChunkUpdate {
    static {
        Utils.loadProviderTestSuite();
    }

    public TestChaCha20Poly1305ChunkUpdate() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite() {
        TestSuite suite = new TestSuite(
                ibm.jceplus.junit.openjceplusfips.TestChaCha20Poly1305ChunkUpdate.class);
        return suite;
    }
}
