/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.util.Arrays;
import java.util.Random;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestHmacSHA1Interop extends BaseTestJunit5Interop {

    static final byte[] key_1 = {(byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b, (byte) 0x0b,
            (byte) 0x0b, (byte) 0x0b, (byte) 0x0b};

    //"Hi There".getBytes();
    static final byte[] data_1 = {(byte) 0x48, (byte) 0x69, (byte) 0x20, (byte) 0x54, (byte) 0x68,
            (byte) 0x65, (byte) 0x72, (byte) 0x65};

    static final byte[] digest_1 = {(byte) 0xb6, (byte) 0x17, (byte) 0x31, (byte) 0x86, (byte) 0x55,
            (byte) 0x05, (byte) 0x72, (byte) 0x64, (byte) 0xe2, (byte) 0x8b, (byte) 0xc0,
            (byte) 0xb6, (byte) 0xfb, (byte) 0x37, (byte) 0x8c, (byte) 0x8e, (byte) 0xf1,
            (byte) 0x46, (byte) 0xbe, (byte) 0x00};

    //"Jefe".getBytes();
    static final byte[] key_2 = {(byte) 0x4a, (byte) 0x65, (byte) 0x66, (byte) 0x65};

    //"what do ya want for nothing?".getBytes();
    static final byte[] data_2 = {(byte) 0x77, (byte) 0x68, (byte) 0x61, (byte) 0x74, (byte) 0x20,
            (byte) 0x64, (byte) 0x6f, (byte) 0x20, (byte) 0x79, (byte) 0x61, (byte) 0x20,
            (byte) 0x77, (byte) 0x61, (byte) 0x6e, (byte) 0x74, (byte) 0x20, (byte) 0x66,
            (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x6e, (byte) 0x6f, (byte) 0x74,
            (byte) 0x68, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x3f};

    static final byte[] digest_2 = {(byte) 0xef, (byte) 0xfc, (byte) 0xdf, (byte) 0x6a, (byte) 0xe5,
            (byte) 0xeb, (byte) 0x2f, (byte) 0xa2, (byte) 0xd2, (byte) 0x74, (byte) 0x16,
            (byte) 0xd5, (byte) 0xf1, (byte) 0x84, (byte) 0xdf, (byte) 0x9c, (byte) 0x25,
            (byte) 0x9a, (byte) 0x7c, (byte) 0x79};

    static final byte[] key_3 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa};

    static final byte[] data_3 = {(byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd};

    static final byte[] digest_3 = {(byte) 0x12, (byte) 0x5d, (byte) 0x73, (byte) 0x42, (byte) 0xb9,
            (byte) 0xac, (byte) 0x11, (byte) 0xcd, (byte) 0x91, (byte) 0xa3, (byte) 0x9a,
            (byte) 0xf4, (byte) 0x8a, (byte) 0xa1, (byte) 0x7b, (byte) 0x4f, (byte) 0x63,
            (byte) 0xf1, (byte) 0x75, (byte) 0xd3};

    static final byte[] key_4 = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05,
            (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a, (byte) 0x0b,
            (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10, (byte) 0x11,
            (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16, (byte) 0x17,
            (byte) 0x18, (byte) 0x19};

    static final byte[] data_4 = {(byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd};

    static final byte[] digest_4 = {(byte) 0x4c, (byte) 0x90, (byte) 0x07, (byte) 0xf4, (byte) 0x02,
            (byte) 0x62, (byte) 0x50, (byte) 0xc6, (byte) 0xbc, (byte) 0x84, (byte) 0x14,
            (byte) 0xf9, (byte) 0xbf, (byte) 0x50, (byte) 0xc8, (byte) 0x6c, (byte) 0x2d,
            (byte) 0x72, (byte) 0x35, (byte) 0xda};

    static final byte[] key_5 = {(byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c, (byte) 0x0c,
            (byte) 0x0c, (byte) 0x0c, (byte) 0x0c};

    //"Test With Truncation".getBytes();
    static final byte[] data_5 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x57, (byte) 0x69, (byte) 0x74, (byte) 0x68, (byte) 0x20, (byte) 0x54,
            (byte) 0x72, (byte) 0x75, (byte) 0x6e, (byte) 0x63, (byte) 0x61, (byte) 0x74,
            (byte) 0x69, (byte) 0x6f, (byte) 0x6e};

    static final byte[] digest_5 = {(byte) 0x4c, (byte) 0x1a, (byte) 0x03, (byte) 0x42, (byte) 0x4b,
            (byte) 0x55, (byte) 0xe0, (byte) 0x7f, (byte) 0xe7, (byte) 0xf2, (byte) 0x7b,
            (byte) 0xe1, (byte) 0xd5, (byte) 0x8b, (byte) 0xb9, (byte) 0x32, (byte) 0x4a,
            (byte) 0x9a, (byte) 0x5a, (byte) 0x04};

    static final byte[] key_6 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
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
    static final byte[] data_6 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20,
            (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65, (byte) 0x72,
            (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e, (byte) 0x20,
            (byte) 0x42, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d,
            (byte) 0x53, (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x4b,
            (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x2d, (byte) 0x20, (byte) 0x48,
            (byte) 0x61, (byte) 0x73, (byte) 0x68, (byte) 0x20, (byte) 0x4b, (byte) 0x65,
            (byte) 0x79, (byte) 0x20, (byte) 0x46, (byte) 0x69, (byte) 0x72, (byte) 0x73,
            (byte) 0x74};

    static final byte[] digest_6 = {(byte) 0xaa, (byte) 0x4a, (byte) 0xe5, (byte) 0xe1, (byte) 0x52,
            (byte) 0x72, (byte) 0xd0, (byte) 0x0e, (byte) 0x95, (byte) 0x70, (byte) 0x56,
            (byte) 0x37, (byte) 0xce, (byte) 0x8a, (byte) 0x3b, (byte) 0x55, (byte) 0xed,
            (byte) 0x40, (byte) 0x21, (byte) 0x12};

    static final byte[] key_7 = {(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
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
    static final byte[] data_7 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
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

    static final byte[] digest_7 = {(byte) 0xe8, (byte) 0xe9, (byte) 0x9d, (byte) 0x0f, (byte) 0x45,
            (byte) 0x23, (byte) 0x7d, (byte) 0x78, (byte) 0x6d, (byte) 0x6b, (byte) 0xba,
            (byte) 0xa7, (byte) 0x96, (byte) 0x5c, (byte) 0x78, (byte) 0x08, (byte) 0xbb,
            (byte) 0xff, (byte) 0x1a, (byte) 0x91};

    //"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
    static final byte[] data_7_20 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74,
            (byte) 0x20, (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67,
            (byte) 0x20, (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65,
            (byte) 0x72, (byte) 0x20, (byte) 0x54, (byte) 0x68};

    static final byte[] digest_7_20 = {(byte) 0x4c, (byte) 0x1a, (byte) 0x03, (byte) 0x42,
            (byte) 0x4b, (byte) 0x55, (byte) 0xe0, (byte) 0x7f, (byte) 0xe7, (byte) 0xf2,
            (byte) 0x7b, (byte) 0xe1, (byte) 0xd5, (byte) 0x8b, (byte) 0xb9, (byte) 0x32,
            (byte) 0x4a, (byte) 0x9a, (byte) 0x5a, (byte) 0x04};

    @Test
    public void test_data1() throws Exception {
        doHmac(data_1, getProviderName(), getInteropProviderName());
        doHmac(data_1, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data2() throws Exception {
        doHmac(data_2, getProviderName(), getInteropProviderName());
        doHmac(data_2, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data3() throws Exception {
        doHmac(data_3, getProviderName(), getInteropProviderName());
        doHmac(data_3, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data4() throws Exception {
        doHmac(data_4, getProviderName(), getInteropProviderName());
        doHmac(data_4, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data5() throws Exception {
        doHmac(data_5, getProviderName(), getInteropProviderName());
        doHmac(data_5, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data6() throws Exception {
        doHmac(data_6, getProviderName(), getInteropProviderName());
        doHmac(data_6, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data7() throws Exception {
        doHmac(data_7, getProviderName(), getInteropProviderName());
        doHmac(data_7, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_payload_512() throws Exception {
        byte[] data_512 = new byte[512];
        Random r = new Random(10);
        r.nextBytes(data_512);
        doHmac(data_512, getProviderName(), getInteropProviderName());
        doHmac(data_512, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_payload_2048() throws Exception {
        byte[] data_2048 = new byte[2048];
        Random r = new Random(10);
        r.nextBytes(data_2048);
        doHmac(data_2048, getProviderName(), getInteropProviderName());
        doHmac(data_2048, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_payload_8192() throws Exception {
        byte[] data_8192 = new byte[8192];
        Random r = new Random(10);
        r.nextBytes(data_8192);
        doHmac(data_8192, getProviderName(), getInteropProviderName());
        doHmac(data_8192, getInteropProviderName(), getProviderName());
    }


    protected void doHmac(byte[] data, String provider, String interopProvider) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA1", provider);
        SecretKey key = keyGen.generateKey();

        Mac mac = Mac.getInstance("HmacSHA1", provider);
        mac.init(key);
        mac.update(data);
        byte[] digest = mac.doFinal();

        Mac mac2 = Mac.getInstance("HmacSHA1", interopProvider);
        mac2.init(key);
        mac2.update(data);
        byte[] digest2 = mac2.doFinal();

        assertTrue(Arrays.equals(digest, digest2), "Mac digest did not equal expected");
    }
}

