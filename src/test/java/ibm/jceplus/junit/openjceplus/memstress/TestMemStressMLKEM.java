/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus.memstress;

import ibm.jceplus.junit.base.memstress.BaseTestMemStressMLKEM;
import ibm.jceplus.junit.openjceplus.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestMemStressMLKEM extends BaseTestMemStressMLKEM {
    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        setPrintheapstats(Boolean.valueOf(
            System.getProperty("com.ibm.jceplus.memstress.printheapstats")));
        String numTimesStr =
            System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            setNumTimes(Integer.valueOf(numTimesStr));
        }
        System.out.println("Testing MLKEM algorithm = " + getAlgo() + getPrintheapstats());
    }
}
