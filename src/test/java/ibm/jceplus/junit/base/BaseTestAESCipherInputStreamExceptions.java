/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Ensure proper exceptions thrown while reading data using a CipherInputStream:
 * - Make sure authenticated algorithms continue to ignore AAD and not throw exceptions.
 * - Make sure other algorithms do not throw exceptions when the stream
 *   calls close() and only throw when a invalid read() errors.
 */
public class BaseTestAESCipherInputStreamExceptions extends BaseTestJunit5 {

    static final SecretKeySpec key = new SecretKeySpec(new byte[16], "AES");
    static final GCMParameterSpec gcmspec = new GCMParameterSpec(128, new byte[16]);
    static final IvParameterSpec iv = new IvParameterSpec(new byte[16]);
    private TestInfo testInfo;

    @BeforeEach
    void init(TestInfo testInfo) {
        this.testInfo = testInfo;
    }

    /**
     * Attempt to create a bad auth tag.
     * 
     * This test:
     *    1) Encrypts 100 bytes.
     *    2) Intentionally corrupts the encrypted data.
     *    3) Ensures that the correct length of data is read after
     *       all available whole blocks of data are read from the
     *       stream. 
     *    4) Reads the last bit of data from the stream to trigger
     *       the AAD calculation. This is expected to fail due to
     *       the corrupt data.
     * @throws Exception
     */
    @Test
    public void gcm_AEADBadTag() throws Exception {
        byte[] read = new byte[200];

        System.out.println("Running " + testInfo.getDisplayName());

        // Encrypt 100 bytes with AES/GCM/NoPadding
        byte[] ct = encryptedText("GCM", 100);
        // Corrupt the encrypted message
        ct = corruptGCM(ct);
        // Create stream for decryption
        CipherInputStream in = getStream("GCM", ct);

        int amountRead = in.read(read);

        // Expect 96 bytes since this is closest block 
        // size we can read without going over.
        assertEquals(96, amountRead);

        // Read one more time to read the rest of the data in
        // the stream. This will trigger the AAD calculation 
        // and cause an intentional exception due to above data 
        // manipulation.
        try {
            in.read(read);
            fail("Expected IOException not thrown.");
        } catch ( IOException e) {
            //Expect nested AEADBadTagException
            assertThat(e.getMessage(), containsString("AEADBadTagException"));
        }
    }

    /**
     * Make use of a short read stream buffer to partially decrypt
     * a buffer.
     * 
     * This test
     *   1) Encrypt 600 bytes with AES/GCM/NoPadding
     *   2) Reads 100 bytes from stream to decrypt the message and closes the stream.
     *   3) Make sure no exception is thrown and validate first byte is as expected.
     */
    @Test
    public void gcm_shortReadAEAD() throws Exception {
        byte[] read = new byte[100];

        System.out.println("Running " + testInfo.getDisplayName());

        byte[] pt = new byte[600];
        pt[0] = 1;
        // Encrypt provided 600 bytes with AES/GCM/NoPadding
        byte[] ct = encryptedText("GCM", pt);
        // Create stream for decryption
        CipherInputStream in = getStream("GCM", ct);

        in.read(read);
        in.close();
        assertEquals(read.length, 100);

        if (read[0] != 1) {
            throw new RuntimeException("Fail: The decrypted text does "
                    + "not match the plaintext: '" + read[0] + "'");
        }
    }

    /**
     * Verify doFinal() exception is suppressed when input stream is not
     * read before it is closed.
     *
     * This test:
     *   1) Encrypt 100 bytes with AES/GCM/NoPadding
     *   2) Changes the last byte to invalidate the authentication tag.
     *   3) Opens a CipherInputStream and the closes it. Never reads from it.
     *
     * There should be no exception thrown.
     */
    @Test
    public void gcm_suppressUnreadCorrupt() throws Exception {

        System.out.println("Running " + testInfo.getDisplayName());

        // Encrypt 100 bytes with AES/GCM/NoPadding
        byte[] ct = encryptedText("GCM", 100);
        // Corrupt the encrypted message
        ct = corruptGCM(ct);
        // Create stream for decryption
        CipherInputStream in = getStream("GCM", ct);
        in.close();
    }

    /**
     * Verify no exception is thrown when 1 byte is read from a GCM stream
     * and then closed.
     * 
     * This test:
     *   1) Encrypt 100 bytes with AES/GCM/NoPadding
     *   2) Read one byte from the stream, expect no exception thrown.
     *   4) Close stream, expect no exception thrown.
     */
    @Test
    public void do_gcm_oneReadByte() throws Exception {

        System.out.println("Running " + testInfo.getDisplayName());

        // Encrypt 100 bytes with AES/GCM/NoPadding
        byte[] ct = encryptedText("GCM", 100);
        // Create stream for decryption
        try (CipherInputStream in = getStream("GCM", ct);) {
            in.read();
        }
    }

    /**
     * Verify no exception is thrown when 1 byte is read from a corrupted GCM stream
     * and then closed.
     *
     * This test:
     *   1) Encrypt 96 bytes with AES/GCM/NoPadding
     *   2) Change the last byte to invalidate the authentication tag.
     *   3) Read one byte from the stream, given that CipherInputStream does
     *      not validate the auth tag and that we have only read one byte
     *      we should expect that no exception is thrown.
     *   4) Close stream, expect no exception thrown.
     */
    @Test
    public void do_gcm_oneReadByteCorrupt() throws Exception {

        System.out.println("Running " + testInfo.getDisplayName());

        // Encrypt 100 bytes with AES/GCM/NoPadding
        byte[] ct = encryptedText("GCM", 96);
        // Corrupt the encrypted message
        ct = corruptGCM(ct);
        // Create stream for decryption and attempt to read one byte.
        // Given that we are asking for one byte which is not a full
        // block size nothing is returned. The auth tag is not checked
        // since we have not read a block and additionally the CipherInputStream
        // does not validate the auth tag.
        try (CipherInputStream in = getStream("GCM", ct);) {
            int read = in.read();
            assertEquals(0, read);
        }
    }

    /**
     * Check that close() does not throw an exception when the whole message is
     * inside the internal buffer (ibuffer) in CipherInputStream and we read
     * one byte and close the stream.
     *
     * This test:
     *   1) Encrypts a 400 byte message with AES/CBC/NoPadding
     *   2) Read one byte from the stream
     *   3) Close and expect no exception
     */
    @Test
    public void do_cbc_shortRead400() throws Exception {

        System.out.println("Running " + testInfo.getDisplayName());

        // Encrypt 400 byte with AES/CBC/NoPadding
        byte[] ct = encryptedText("CBC", 400);
        // Create stream with encrypted data
        CipherInputStream in = getStream("CBC", ct);

        in.read();
        in.close();
    }

    /**
     * Check that exception is thrown when message is fully read.
     *
     * This test:
     *   1) Encrypts a 96 byte message with AES/CBC/NoPadding
     *   2) Create a stream that sends 95 bytes.
     *   3) Read stream to the end
     *   4) Expect IOException that contains a IllegalBlockSize exception to be thrown
     */
    @Test
    public void do_cbc_readAllIllegalBlockSize() throws Exception {
        byte[] read = new byte[200];

        System.out.println("Running " + testInfo.getDisplayName());

        // Encrypt 96 byte with AES/CBC/NoPadding
        byte[] ct = encryptedText("CBC", 96);
        // Create a stream with only 95 bytes of encrypted data
        CipherInputStream in = getStream("CBC", ct, 95);

        try {
            int s, size = 0;
            while ((s = in.read(read)) != -1) {
                size += s;
            }
            fail("IOException expected.");
        } catch (IOException e) {
            // We expect a IOException.
        };
    }

    /**
     * Generic method to create encrypted text.
     */
    private byte[] encryptedText(String mode, int length) throws Exception {
        return encryptedText(mode, new byte[length]);
    }

    /**
     * Generic method to create encrypted text.
     */
    private byte[] encryptedText(String mode, byte[] pt) throws Exception {
        Cipher c;
        if (mode.compareTo("GCM") == 0) {
            c = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            c.init(Cipher.ENCRYPT_MODE, key, gcmspec);
        } else if (mode.compareTo("CBC") == 0) {
            c = Cipher.getInstance("AES/CBC/NoPadding", getProviderName());
            c.init(Cipher.ENCRYPT_MODE, key, iv);
        } else {
            return null;
        }

        return c.doFinal(pt);
    }

    /**
     * Generic method to get a properly setup CipherInputStream.
     */
    private CipherInputStream getStream(String mode, byte[] ct) throws Exception {
        return getStream(mode, ct, ct.length);
    }

    /**
     * Generic method to get a properly setup CipherInputStream.
     */
    private CipherInputStream getStream(String mode, byte[] ct, int length) throws Exception {
        Cipher c;

        if (mode.compareTo("GCM") == 0) {
            c = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
            c.init(Cipher.DECRYPT_MODE, key, gcmspec);
        } else if (mode.compareTo("CBC") == 0) {
            c = Cipher.getInstance("AES/CBC/NoPadding", getProviderName());
            c.init(Cipher.DECRYPT_MODE, key, iv);
        } else {
            return null;
        }

        return new CipherInputStream(new ByteArrayInputStream(ct, 0, length), c);

    }

    /**
     * Generic method for corrupting a GCM message. Change the last
     * byte of the authentication tag
     */
    private static byte[] corruptGCM(byte[] ct) {
        ct[ct.length - 1] = (byte) (ct[ct.length - 1] + 1);
        return ct;
    }
}
