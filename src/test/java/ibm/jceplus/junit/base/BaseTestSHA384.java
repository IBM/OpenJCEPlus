/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.util.Arrays;

public class BaseTestSHA384 extends BaseTestMessageDigestClone {
    static boolean warmup = false;

    //--------------------------------------------------------------------------
    //
    //

    final byte[] input_1 = {(byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61,
            (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61};

    final byte[] result_1 = {(byte) 0x9d, (byte) 0x0e, (byte) 0x18, (byte) 0x09, (byte) 0x71,
            (byte) 0x64, (byte) 0x74, (byte) 0xcb, (byte) 0x08, (byte) 0x6e, (byte) 0x83,
            (byte) 0x4e, (byte) 0x31, (byte) 0x0a, (byte) 0x4a, (byte) 0x1c, (byte) 0xed,
            (byte) 0x14, (byte) 0x9e, (byte) 0x9c, (byte) 0x00, (byte) 0xf2, (byte) 0x48,
            (byte) 0x52, (byte) 0x79, (byte) 0x72, (byte) 0xce, (byte) 0xc5, (byte) 0x70,
            (byte) 0x4c, (byte) 0x2a, (byte) 0x5b, (byte) 0x07, (byte) 0xb8, (byte) 0xb3,
            (byte) 0xdc, (byte) 0x38, (byte) 0xec, (byte) 0xc4, (byte) 0xeb, (byte) 0xae,
            (byte) 0x97, (byte) 0xdd, (byte) 0xd8, (byte) 0x7f, (byte) 0x3d, (byte) 0x89,
            (byte) 0x85};

    final byte[] input_2 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] result_2 = {(byte) 0xcb, (byte) 0x00, (byte) 0x75, (byte) 0x3f, (byte) 0x45,
            (byte) 0xa3, (byte) 0x5e, (byte) 0x8b, (byte) 0xb5, (byte) 0xa0, (byte) 0x3d,
            (byte) 0x69, (byte) 0x9a, (byte) 0xc6, (byte) 0x50, (byte) 0x07, (byte) 0x27,
            (byte) 0x2c, (byte) 0x32, (byte) 0xab, (byte) 0x0e, (byte) 0xde, (byte) 0xd1,
            (byte) 0x63, (byte) 0x1a, (byte) 0x8b, (byte) 0x60, (byte) 0x5a, (byte) 0x43,
            (byte) 0xff, (byte) 0x5b, (byte) 0xed, (byte) 0x80, (byte) 0x86, (byte) 0x07,
            (byte) 0x2b, (byte) 0xa1, (byte) 0xe7, (byte) 0xcc, (byte) 0x23, (byte) 0x58,
            (byte) 0xba, (byte) 0xec, (byte) 0xa1, (byte) 0x34, (byte) 0xc8, (byte) 0x25,
            (byte) 0xa7};

    final byte[] input_3 = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65,
            (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x62, (byte) 0x63, (byte) 0x64,
            (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x63,
            (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x69,
            (byte) 0x6a, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68,
            (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x65, (byte) 0x66, (byte) 0x67,
            (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x66,
            (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c,
            (byte) 0x6d, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x68, (byte) 0x69, (byte) 0x6a,
            (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x69,
            (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f,
            (byte) 0x70, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d,
            (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x6c,
            (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x72,
            (byte) 0x73, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71,
            (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x6e, (byte) 0x6f, (byte) 0x70,
            (byte) 0x71, (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x75};

    final byte[] result_3 = {(byte) 0x09, (byte) 0x33, (byte) 0x0c, (byte) 0x33, (byte) 0xf7,
            (byte) 0x11, (byte) 0x47, (byte) 0xe8, (byte) 0x3d, (byte) 0x19, (byte) 0x2f,
            (byte) 0xc7, (byte) 0x82, (byte) 0xcd, (byte) 0x1b, (byte) 0x47, (byte) 0x53,
            (byte) 0x11, (byte) 0x1b, (byte) 0x17, (byte) 0x3b, (byte) 0x3b, (byte) 0x05,
            (byte) 0xd2, (byte) 0x2f, (byte) 0xa0, (byte) 0x80, (byte) 0x86, (byte) 0xe3,
            (byte) 0xb0, (byte) 0xf7, (byte) 0x12, (byte) 0xfc, (byte) 0xc7, (byte) 0xc7,
            (byte) 0x1a, (byte) 0x55, (byte) 0x7e, (byte) 0x2d, (byte) 0xb9, (byte) 0x66,
            (byte) 0xc3, (byte) 0xe9, (byte) 0xfa, (byte) 0x91, (byte) 0x74, (byte) 0x60,
            (byte) 0x39};

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestSHA384(String providerName) {
        super(providerName, "SHA-384");
        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA384() throws Exception {

        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);

        for (int i = 0; i < 100000; i++)
            md.update(input_1);
        byte[] digest = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(digest, result_1));

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA384_SingleBlock() throws Exception {

        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);
        byte[] digest = md.digest(input_2);

        assertTrue("Digest did not match expected", Arrays.equals(digest, result_2));

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA384_reset() throws Exception {

        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);
        md.update(input_1);
        md.reset();
        md.update(input_2);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, result_2));

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA384_MultiBlock() throws Exception {

        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);

        byte[] digest = md.digest(input_3);

        assertTrue("Digest did not match expected", Arrays.equals(digest, result_3));

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA384_digestLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);
        int digestLength = md.getDigestLength();
        boolean isExpectedValue = (digestLength == 48);
        assertTrue("Unexpected digest length", isExpectedValue);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void warmup() throws Exception {

        try {
            MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);
            for (long i = 0; i < 10000; i++) {
                md.update(input_1);
                md.digest();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
