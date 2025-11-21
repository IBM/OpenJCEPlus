/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestHmacMD5 extends BaseTestJunit5 {
    final byte[] key_1 = {(byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b};

    //"Hi There".getBytes();
    final byte[] data_1 = {(byte) 0x48, (byte) 0x69, (byte) 0x20, (byte) 0x54, (byte) 0x68,
            (byte) 0x65, (byte) 0x72, (byte) 0x65};

    final byte[] digest_1 = {(byte) 0x92, (byte) 0x94, (byte) 0x72, (byte) 0x7a, (byte) 0x36,
            (byte) 0x38, (byte) 0xbb, (byte) 0x1c, (byte) 0x13, (byte) 0xf4, (byte) 0x8e,
            (byte) 0xf8, (byte) 0x15, (byte) 0x8b, (byte) 0xfc, (byte) 0x9d};

    //"Jefe".getBytes();
    final byte[] key_2 = {(byte) 0x4a, (byte) 0x65, (byte) 0x66, (byte) 0x65};

    //"what do ya want for nothing?".getBytes();
    final byte[] data_2 = {(byte) 0x77, (byte) 0x68, (byte) 0x61, (byte) 0x74, (byte) 0x20,
            (byte) 0x64, (byte) 0x6f, (byte) 0x20, (byte) 0x79, (byte) 0x61, (byte) 0x20,
            (byte) 0x77, (byte) 0x61, (byte) 0x6e, (byte) 0x74, (byte) 0x20, (byte) 0x66,
            (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x6e, (byte) 0x6f, (byte) 0x74,
            (byte) 0x68, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x3f};

    final byte[] digest_2 = {(byte) 0x75, (byte) 0x0c, (byte) 0x78, (byte) 0x3e, (byte) 0x6a,
            (byte) 0xb0, (byte) 0xb5, (byte) 0x03, (byte) 0xea, (byte) 0xa8, (byte) 0x6e,
            (byte) 0x31, (byte) 0x0a, (byte) 0x5d, (byte) 0xb7, (byte) 0x38};

    final byte[] key_3 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa};

    final byte[] data_3 = {(byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd};

    final byte[] digest_3 = {(byte) 0x56, (byte) 0xbe, (byte) 0x34, (byte) 0x52, (byte) 0x1d,
            (byte) 0x14, (byte) 0x4c, (byte) 0x88, (byte) 0xdb, (byte) 0xb8, (byte) 0xc7,
            (byte) 0x33, (byte) 0xf0, (byte) 0xe8, (byte) 0xb3, (byte) 0xf6};

    final byte[] key_4 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11,
            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19};

    final byte[] data_4 = {(byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd};

    final byte[] digest_4 = {(byte) 0x69, (byte) 0x7e, (byte) 0xaf, (byte) 0x0a, (byte) 0xca,
            (byte) 0x3a, (byte) 0x3a, (byte) 0xea, (byte) 0x3a, (byte) 0x75, (byte) 0x16,
            (byte) 0x47, (byte) 0x46, (byte) 0xff, (byte) 0xaa, (byte) 0x79};

    final byte[] key_5 = {(byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c};

    //"Test With Truncation".getBytes(); ASCII//{0xcd};
    final byte[] data_5 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x57, (byte) 0x69, (byte) 0x74, (byte) 0x68, (byte) 0x20, (byte) 0x54,
            (byte) 0x72, (byte) 0x75, (byte) 0x6E, (byte) 0x63, (byte) 0x61, (byte) 0x74,
            (byte) 0x69, (byte) 0x6F, (byte) 0x6E};

    final byte[] digest_5 = {(byte) 0x56, (byte) 0x46, (byte) 0x1e, (byte) 0xf2, (byte) 0x34,
            (byte) 0x2e, (byte) 0xdc, (byte) 0x00, (byte) 0xf9, (byte) 0xba, (byte) 0xb9,
            (byte) 0x95, (byte) 0x69, (byte) 0x0e, (byte) 0xfd, (byte) 0x4c};

    final byte[] key_6 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa};

    //"Test Using Larger Than Block-Size Key - Hash Key First".getBytes();//{0xcd};
    final byte[] data_6 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20,
            (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65, (byte) 0x72,
            (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e, (byte) 0x20,
            (byte) 0x42, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d,
            (byte) 0x53, (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x4b,
            (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x2d, (byte) 0x20, (byte) 0x48,
            (byte) 0x61, (byte) 0x73, (byte) 0x68, (byte) 0x20, (byte) 0x4b, (byte) 0x65,
            (byte) 0x79, (byte) 0x20, (byte) 0x46, (byte) 0x69, (byte) 0x72, (byte) 0x73,
            (byte) 0x74};

    final byte[] digest_6 = {(byte) 0x6b, (byte) 0x1a, (byte) 0xb7, (byte) 0xfe, (byte) 0x4b,
            (byte) 0xd7, (byte) 0xbf, (byte) 0x8f, (byte) 0x0b, (byte) 0x62, (byte) 0xe6,
            (byte) 0xce, (byte) 0x61, (byte) 0xb9, (byte) 0xd0, (byte) 0xcd};

    final byte[] key_7 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa};

    //"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
    final byte[] data_7 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20,
            (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65, (byte) 0x72,
            (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e, (byte) 0x20,
            (byte) 0x42, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d,
            (byte) 0x53, (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x4b,
            (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
            (byte) 0x20, (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65,
            (byte) 0x72, (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e,
            (byte) 0x20, (byte) 0x4f, (byte) 0x6e, (byte) 0x65, (byte) 0x20, (byte) 0x42,
            (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d, (byte) 0x53,
            (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x44, (byte) 0x61,
            (byte) 0x74, (byte) 0x61};

    final byte[] digest_7 = {(byte) 0x6f, (byte) 0x63, (byte) 0x0f, (byte) 0xad, (byte) 0x67,
            (byte) 0xcd, (byte) 0xa0, (byte) 0xee, (byte) 0x1f, (byte) 0xb1, (byte) 0xf5,
            (byte) 0x62, (byte) 0xdb, (byte) 0x3a, (byte) 0xa5, (byte) 0x3e};

    @Test
    public void testHmacMD5_key1() throws Exception {

        Mac mac = Mac.getInstance("HmacMD5", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacMD5");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");

    }

    @Test
    public void testHmacMD5_key2() throws Exception {
        Mac mac = Mac.getInstance("HmacMD5", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_2, "HmacMD5");
        mac.init(key);
        mac.update(data_2);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_2), "Mac digest did not equal expected");

    }

    @Test
    public void testHmacMD5_key3() throws Exception {

        Mac mac = Mac.getInstance("HmacMD5", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_3, "HmacMD5");
        mac.init(key);
        mac.update(data_3);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_3), "Mac digest did not equal expected");

    }

    @Test
    public void testHmacMD5_key4() throws Exception {

        Mac mac = Mac.getInstance("HmacMD5", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_4, "HmacMD5");
        mac.init(key);
        mac.update(data_4);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_4), "Mac digest did not equal expected");

    }

    @Test
    public void testHmacMD5_key5() throws Exception {

        Mac mac = Mac.getInstance("HmacMD5", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_5, "HmacMD5");
        mac.init(key);
        mac.update(data_5);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_5), "Mac digest did not equal expected");

    }

    @Test
    public void testHmacMD5_key6() throws Exception {

        Mac mac = Mac.getInstance("HmacMD5", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_6, "HmacMD5");
        mac.init(key);
        mac.update(data_6);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_6), "Mac digest did not equal expected");

    }

    @Test
    public void testHmacMD5_key7() throws Exception {

        Mac mac = Mac.getInstance("HmacMD5", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_7, "HmacMD5");
        mac.init(key);
        mac.update(data_7);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_7), "Mac digest did not equal expected");

    }
}
