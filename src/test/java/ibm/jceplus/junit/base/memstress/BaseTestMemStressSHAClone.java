/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base.memstress;

import ibm.jceplus.junit.base.BaseTestJunit5;
import java.security.MessageDigest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BaseTestMemStressSHAClone extends BaseTestJunit5 {

    /* This test by default tests SHA-256 */


    byte[] input_1, result_1, input_2, result_2;

    final byte[] def_input_1 = {(byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61,
            (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61};

    final byte[] def_result_1 = {(byte) 0xcd, (byte) 0xc7, (byte) 0x6e, (byte) 0x5c, (byte) 0x99,
            (byte) 0x14, (byte) 0xfb, (byte) 0x92, (byte) 0x81, (byte) 0xa1, (byte) 0xc7,
            (byte) 0xe2, (byte) 0x84, (byte) 0xd7, (byte) 0x3e, (byte) 0x67, (byte) 0xf1,
            (byte) 0x80, (byte) 0x9a, (byte) 0x48, (byte) 0xa4, (byte) 0x97, (byte) 0x20,
            (byte) 0x0e, (byte) 0x04, (byte) 0x6d, (byte) 0x39, (byte) 0xcc, (byte) 0xc7,
            (byte) 0x11, (byte) 0x2c, (byte) 0xd0};

    final byte[] def_input_2 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] def_result_2 = {(byte) 0xba, (byte) 0x78, (byte) 0x16, (byte) 0xbf, (byte) 0x8f,
            (byte) 0x01, (byte) 0xcf, (byte) 0xea, (byte) 0x41, (byte) 0x41, (byte) 0x40,
            (byte) 0xde, (byte) 0x5d, (byte) 0xae, (byte) 0x22, (byte) 0x23, (byte) 0xb0,
            (byte) 0x03, (byte) 0x61, (byte) 0xa3, (byte) 0x96, (byte) 0x17, (byte) 0x7a,
            (byte) 0x9c, (byte) 0xb4, (byte) 0x10, (byte) 0xff, (byte) 0x61, (byte) 0xf2,
            (byte) 0x00, (byte) 0x15, (byte) 0xad};



    int numTimes = 10000;

    protected String digestAlg = "SHA-256";

    @BeforeEach
    public void setUp() throws Exception {
        String numTimesStr = System.getProperty("com.ibm.jceplus.memstress.numtimes");
        if (numTimesStr != null) {
            numTimes = Integer.valueOf(numTimesStr);
        }
        System.out.println("Testing " + digestAlg);
    }

    @Test
    public void testSHA() throws Exception {
        MessageDigest md = MessageDigest.getInstance(digestAlg, getProviderName());
        MessageDigest[] mdCopies = new MessageDigest[numTimes];

        for (int i = 0; i < numTimes; i++) {
            mdCopies[i] = (MessageDigest) md.clone();
        }

        byte[] digest;
        for (int i = 0; i < numTimes; i++) {
            digest = mdCopies[i].digest(input_1);
            assertArrayEquals(def_result_1, digest, "Digest for clone " + i + " did not match expected");
        }
    }
}
