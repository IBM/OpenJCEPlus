/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.nio.ByteBuffer;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class BaseTestResetByteBuffer extends BaseTestJunit5 {

    Cipher c;
    SecretKey key;
    ByteBuffer in, out;
    byte[] data = new byte[1500];
    byte encrypted[];

    private static Stream<Arguments> resetByteBufferTestParameters() {
        return Stream.of(
            Arguments.of("AES/GCM/NoPadding", false, true, true, true),
            Arguments.of("AES/GCM/NoPadding", false, true, true, true),
            Arguments.of("AES/GCM/NoPadding", false, true, true, false),
            Arguments.of("AES/GCM/NoPadding", false, true, true, false),
            Arguments.of("AES/GCM/NoPadding", false, true, false, true),
            Arguments.of("AES/GCM/NoPadding", false, true, false, true),
            Arguments.of("AES/GCM/NoPadding", false, true, false, false),
            Arguments.of("AES/GCM/NoPadding", false, true, false, false),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, true, true),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, true, true),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, true, false),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, true, false),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, false, true),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, false, true),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, false, false),
            Arguments.of("AES/CBC/PKCS5Padding", true, true, false, false),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, true, true),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, true, true),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, true, false),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, true, false),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, false, true),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, false, true),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, false, false),
            Arguments.of("AES/CBC/PKCS5Padding", false, true, false, false)
        );
    }

    @ParameterizedTest
    @MethodSource("resetByteBufferTestParameters")
    public void doTestResetByteBuffer(String algo, boolean encrypt, boolean direct, boolean updateFirst, boolean updateSecond) throws Exception {
        // Instantiate algorithm and create appropriate key.
        c = Cipher.getInstance(algo, getProviderName());
        String a[] = algo.split("/");
        KeyGenerator kg = KeyGenerator.getInstance(a[0], getProviderName());
        key = kg.generateKey();
        
        // Create encrypted data.
        c.init(Cipher.ENCRYPT_MODE, key, c.getParameters());
        encrypted = new byte[c.getOutputSize(data.length)];
        c.doFinal(data, 0, data.length, encrypted, 0);

        // Initialize for encryption or decryption using byte buffers.
        if (encrypt == true) {
            initializeEncrypt(direct);
        } else {
            initializeDecrypt(direct);
        }

        // Perform first operation, either an update or dofinal.
        if (updateFirst == true) {
            doUpdate();
        } else {
            doFinal();
        }

        // Perform second operation, either an update or dofinal.
        if (updateSecond == true) {
            doUpdate();
        } else {
            doFinal();
        }
    }

    private void initializeDecrypt(boolean direct) throws Exception {
        // Allocate ByteBuffer optionally a set of direct ones.
        if (direct) {
            in = ByteBuffer.allocateDirect(encrypted.length);
            out = ByteBuffer.allocateDirect(encrypted.length);
        } else {
            in = ByteBuffer.allocate(encrypted.length);
            out = ByteBuffer.allocate(encrypted.length);
        }
        in.put(encrypted);
        in.flip();
        c.init(Cipher.DECRYPT_MODE, key, c.getParameters());
    }

    private void initializeEncrypt(boolean direct) throws Exception {
        // Allocate ByteBuffer optionally a set of direct ones.
        if (direct) {
            in = ByteBuffer.allocateDirect(data.length);
            out = ByteBuffer.allocateDirect(c.getOutputSize(data.length));
        } else {
            in = ByteBuffer.allocate(data.length);
            out = ByteBuffer.allocate(c.getOutputSize(data.length));
        }
        c.init(Cipher.ENCRYPT_MODE, key, c.getParameters());
    }

    private void doUpdate() throws Exception {
        int updateLen = data.length / 2;
        in.limit(updateLen);
        c.update(in, out);
        in.limit(in.capacity());
        c.doFinal(in, out);
        in.flip();
        out.position(0);
        out.limit(out.capacity());
    }

    private void doFinal() throws Exception {
        c.doFinal(in, out);
        in.flip();
        out.position(0);
        out.limit(out.capacity());
    }
}
