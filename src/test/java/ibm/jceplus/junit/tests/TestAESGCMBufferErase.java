/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import ibm.jceplus.junit.tests.parameters.resolvers.AESKeySizeListParameterResolver;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ExtendWith(AESKeySizeListParameterResolver.class)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#keySizesAndProviders")
public class TestAESGCMBufferErase extends BaseTest {

    @Parameter(0)
    int keysize;

    @Parameter(1)
    TestProvider provider;

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int    EXTRA          = 8;    // bytes either side of plaintext
    private static final int    TAG_LEN        = 16;   // bytes
    private static final int    PT_MAX_LEN     = 1028;
    private static final byte   SENTINEL       = (byte) 0xAA;

    // Shared across all test instances - initialised once in @BeforeAll
    private static SecretKey        KEY;
    private static GCMParameterSpec SPEC;
    private static byte[]           PT;   // plaintext filled with 0x06
    private static byte[]           DST;  // [extra | recovered | extra] filled with SENTINEL

    // -----------------------------------------------------------------------
    // Simple holder for (plainTextLen, ciphertext) pairs
    // -----------------------------------------------------------------------
    static final class TestVector {
        final int    plainTextLen;
        final byte[] ct;

        TestVector(int plainTextLen, byte[] ct) {
            this.plainTextLen = plainTextLen;
            this.ct    = ct;
        }
    }

    // -----------------------------------------------------------------------
    // One-time setup - mirrors the original static initialiser
    // -----------------------------------------------------------------------
    @BeforeEach
    protected void setUp() throws Exception {
        setKeySize(keysize);
        setAndInsertProvider(provider);
        SecureRandom random = new SecureRandom();
        byte[]       rand16 = new byte[16];
        random.nextBytes(rand16);

        KEY  = new SecretKeySpec(rand16, "AES");
        SPEC = new GCMParameterSpec(TAG_LEN << 3, rand16);

        PT  = new byte[PT_MAX_LEN];
        DST = new byte[EXTRA + PT_MAX_LEN + EXTRA];

        Arrays.fill(PT,  (byte) 6);
        Arrays.fill(DST, SENTINEL);
    }

    // -----------------------------------------------------------------------
    // Helper: build a ciphertext with a deliberately corrupted tag
    // -----------------------------------------------------------------------
    private TestVector setupTestVector(int len) throws Exception {
        Cipher c = Cipher.getInstance(TRANSFORMATION, provider.getProviderName());
        c.init(Cipher.ENCRYPT_MODE, KEY, SPEC);
        byte[] ct = c.doFinal(PT, 0, len);
        ct[ct.length - 1] ^= 0x01; // flip last tag bit -> forces AEADBadTagException
        return new TestVector(len, ct);
    }

    // -----------------------------------------------------------------------
    // Helper: decrypt and assert AEADBadTagException is thrown
    // -----------------------------------------------------------------------
    private void doDecrypt(ByteBuffer src, ByteBuffer dst) throws Exception {
        Cipher dec = Cipher.getInstance(TRANSFORMATION, provider.getProviderName());
        dec.init(Cipher.DECRYPT_MODE, KEY, SPEC);
        try {
            dec.doFinal(src, dst);
            assertTrue(false, "Failed - AEADBadTagException was not thrown:\n");
        } catch (AEADBadTagException e) {
            // expected - tag is intentionally corrupted
        }
    }

    // -----------------------------------------------------------------------
    // Test 1: in-memory DirectByteBuffer
    // -----------------------------------------------------------------------
    @Test
    public void testDirect() throws Exception {
        for (int plainTextLen = 1; plainTextLen <= PT.length; plainTextLen++) {
            TestVector tv = setupTestVector(plainTextLen);

            ByteBuffer dst = ByteBuffer.allocateDirect(DST.length);
            dst.put(DST);
            dst.flip();
            dst.position(EXTRA);

            ByteBuffer src = ByteBuffer.wrap(tv.ct);

            doDecrypt(src, dst);

            dst.rewind();

            for (int i = 0; i < EXTRA; i++) {
                if (dst.get() != SENTINEL) {
                    assertTrue(false, "Corrupted leading bytes at index " + i + " (plainTextLen=" + plainTextLen + ")");
                }
            }
            for (int i = 0; i < tv.plainTextLen; i++) {
                byte value = dst.get();
                if (value != SENTINEL && value != 0) {
                    assertTrue(false, "Possible leak of data at plaintext index " + i + " (plainTextLen=" + plainTextLen + ")");
                }
            }
            for (int i = 0; i < EXTRA; i++) {
                if (dst.get() != SENTINEL) {
                    assertTrue(false, "Corrupted trailing bytes at index " + i + " (plainTextLen=" + plainTextLen + ")");
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: MappedByteBuffer backed by a real file -> checks on-disk erasure
    // -----------------------------------------------------------------------
    @Test
    public void testMapped() throws Exception {
        for (int plainTextLen = 1; plainTextLen <= PT.length; plainTextLen++) {
            TestVector tv = setupTestVector(plainTextLen);

            File f = File.createTempFile("gcm_buffer_erase", ".bin");
            f.deleteOnExit();

            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(DST);
            }

            try (RandomAccessFile raf = new RandomAccessFile(f, "rw");
                 FileChannel ch = raf.getChannel()) {

                MappedByteBuffer dst = ch.map(FileChannel.MapMode.READ_WRITE, 0, DST.length);
                dst.position(EXTRA);

                ByteBuffer src = ByteBuffer.wrap(tv.ct);
                doDecrypt(src, dst);

                try {
                    dst.force();
                } catch (Throwable ignore) { }
            }

            // Re-read from disk independently to confirm on-disk erasure
            try (FileInputStream fis = new FileInputStream(f)) {
                for (int i = 0; i < EXTRA; i++) {
                    if ((byte) fis.read() != SENTINEL) {
                        assertTrue(false, "Corrupted leading bytes at index " + i + " (plainTextLen=" + plainTextLen + ")");
                    }
                }
                for (int i = 0; i < tv.plainTextLen; i++) {
                    byte value = (byte) fis.read();
                    if (value != SENTINEL && value != 0) {
                        assertTrue(false, "Possible leak of data at plaintext index " + i + " (plainTextLen=" + plainTextLen + ")");
                    }
                }
                for (int i = 0; i < EXTRA; i++) {
                    if ((byte) fis.read() != SENTINEL) {
                        assertTrue(false, "Corrupted trailing bytes at index " + i + " (plainTextLen=" + plainTextLen + ")");
                    }
                }
            }
        }
    }
}
