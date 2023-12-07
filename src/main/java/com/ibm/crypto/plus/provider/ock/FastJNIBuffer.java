/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
            byteBuffer.put(index, src, offset, length);
        }
    }

    public void get(int index, byte[] dst, int offset, int length) {
        if (index + length > capacity) {
            throw new RuntimeException("Native array index out of bound.");
        }
        if (dst != null) {
            byteBuffer.get(index, dst, offset, length);
        }
    }
}
