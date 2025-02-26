/*
 * Copyright IBM Corp. 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BaseTestSHA256Clone_SharedMD extends BaseTestJunit5 {
    static MessageDigest md = null;

    final byte[] input = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] result = {(byte) 0xba, (byte) 0x78, (byte) 0x16, (byte) 0xbf, (byte) 0x8f,
            (byte) 0x01, (byte) 0xcf, (byte) 0xea, (byte) 0x41, (byte) 0x41, (byte) 0x40,
            (byte) 0xde, (byte) 0x5d, (byte) 0xae, (byte) 0x22, (byte) 0x23, (byte) 0xb0,
            (byte) 0x03, (byte) 0x61, (byte) 0xa3, (byte) 0x96, (byte) 0x17, (byte) 0x7a,
            (byte) 0x9c, (byte) 0xb4, (byte) 0x10, (byte) 0xff, (byte) 0x61, (byte) 0xf2,
            (byte) 0x00, (byte) 0x15, (byte) 0xad};

    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException {
        setAlgorithm("SHA256");
        if (md == null) {
            md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        }
    }

    @Test
    public void testCloneSharedMD() throws Exception {

        MessageDigest mdCopy = (MessageDigest) md.clone();
        mdCopy.update(input);
        byte[] digest = mdCopy.digest();

        assertArrayEquals(result, digest, "Digest did not match expected");
    }
}
