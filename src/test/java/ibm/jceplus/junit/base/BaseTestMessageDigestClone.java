/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

abstract public class BaseTestMessageDigestClone extends BaseTest {
    // message digest algorithm to be used in all tests
    final String algorithm;

    final byte[] input_1 = {(byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61,
            (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61};

    final byte[] input_2 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] input_3 = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x62,
            (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x63, (byte) 0x64, (byte) 0x65,
            (byte) 0x66, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x65,
            (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x66, (byte) 0x67, (byte) 0x68,
            (byte) 0x69, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x68,
            (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x69, (byte) 0x6a, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x70, (byte) 0x71};

    public BaseTestMessageDigestClone(String providerName, String algorithm) {
        super(providerName);
        this.algorithm = algorithm;
    }

    public void testUpdateCloneSameUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);

        md.update(input_1);

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_2);

        assertArrayEquals(digest2, digest1, "Digest of original did not match clone's digest");
    }

    public void testUpdateCloneDifferentUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);

        md.update(input_1);

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_3);

        assertFalse("Digest of original matches clone's digest when it shouldn't", Arrays.equals(digest1, digest2));
    }

    public void testCloneSameUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_2);

        assertArrayEquals(digest2, digest1, "Digest of original did not match clone's digest");
    }

    public void testCloneDifferentUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(this.algorithm, providerName);

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_3);

        assertFalse("Digest of original matches clone's digest when it shouldn't", Arrays.equals(digest1, digest2));
    }
}
