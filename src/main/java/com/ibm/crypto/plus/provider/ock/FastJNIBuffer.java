/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.nio.ByteBuffer;

class FastJNIBuffer {
    private long pointer;
    private ByteBuffer byteBuffer;
    private int capacity;

    public native int init();

    private FastJNIBuffer(int capacity) {
        byteBuffer = ByteBuffer.allocateDirect(capacity);
    }

    public long pointer() {
        return pointer;
    }

    public static FastJNIBuffer create(int capacity) {
        FastJNIBuffer b = new FastJNIBuffer(capacity);
        b.pointer = NativeInterface.getByteBufferPointer(b.byteBuffer);
        b.capacity = capacity;
        return b;
    }

    public void put(int index, byte[] src, int offset, int length) {
        if (index + length > capacity) {
            throw new RuntimeException("Native array index out of bound.");
        }
        if (src != null) {
            byteBuffer.position(index);
            byteBuffer.put(src, offset, length);
        }
    }

    public void get(int index, byte[] dst, int offset, int length) {
        if (index + length > capacity) {
            throw new RuntimeException("Native array index out of bound.");
        }
        if (dst != null) {
            byteBuffer.position(index);
            byteBuffer.get(dst, offset, length);
        }
    }
}
