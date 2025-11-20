/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * This class accepts byte array input and returns that input minus the last
 * number of bytes as defined by the size. 
 * It buffers the input until the delay size number of bytes is received and then outputs the bytes in the
 * same order they were received.
 * This class can be used to avoid processing data at the end of a byte array stream until required.
 * flush should be called to obtain any data that may be left.
 */
public final class ByteArrayOutputDelay {
    public static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

    private static final int DEFAULT_BYTE_DELAY = 16;
    public static final int MAX_BYTE_DELAY = 65536; //Only used to protect against "unreasonable" memory usage

    private int byteDelay = 0;
    private ByteArrayOutputStream byteArrayOutputStream = null;

    public ByteArrayOutputDelay() {
        super();
        init(DEFAULT_BYTE_DELAY);
    }

    /**
     * @param byteDelay number of bytes to delay by; maximum is 65536 
     */
    public ByteArrayOutputDelay(int byteDelay) {
        super();
        if (byteDelay > MAX_BYTE_DELAY) {
            throw new IllegalArgumentException("Maximum delay allow is " + MAX_BYTE_DELAY);
        }
        init(byteDelay);
    }

    private void init(int byteDelay) {
        if (0 > byteDelay) {
            throw new IllegalArgumentException(
                    "Size must be greater than zero; given: " + byteDelay);
        }
        byteArrayOutputStream = new ByteArrayOutputStream(byteDelay);
        this.byteDelay = byteDelay;
    }

    /**
     * @param input                - input byte array to be delayed
     * @param inputOffset          - offset into input to start processing from
     * @param numberOfBytesToWrite - number of bytes to process from the input
     * @return byte array containing input data from size byte ago. If data less
     *         than the size of the buffer has been input EMPTY_ARRAY will be
     *         returned
     * @throws IOException
     */
    public byte[] write(byte[] input, int inputOffset, int numberOfBytesToWrite) {
        if ((null == input) || (inputOffset >= input.length) || (numberOfBytesToWrite < 1)) {
            return EMPTY_BYTE_ARRAY;
        }

        byteArrayOutputStream.write(input, inputOffset, numberOfBytesToWrite);
        int overflowCount = byteArrayOutputStream.size() - byteDelay;
        if (overflowCount < 1) {
            return EMPTY_BYTE_ARRAY;
        }

        byte[] allBytes = byteArrayOutputStream.toByteArray();
        byte[] overflow = Arrays.copyOfRange(allBytes, 0, overflowCount);
        byte[] keepBytes = Arrays.copyOfRange(allBytes, overflowCount, allBytes.length);
        // byteArrayOutputStream.close(); //ByteArrayOutputStream close has no effect
        byteArrayOutputStream = new ByteArrayOutputStream(byteDelay);
        byteArrayOutputStream.write(keepBytes, 0, byteDelay);

        return overflow;
    }

    /**
     * @return any bytes left; otherwise EMPTY_BYTE_ARRAY
     */
    public byte[] flush() {
        byte[] allBytes = byteArrayOutputStream.toByteArray();
        if ((null == allBytes) || (0 == allBytes.length)) {
            return EMPTY_BYTE_ARRAY;
        }
        return allBytes;
    }

    public int getByteDelay() {
        return byteDelay;
    }

}
