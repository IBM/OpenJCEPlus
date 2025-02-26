/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

import java.nio.ByteBuffer;

class IOScheme {

    protected ByteBuffer input;
    protected ByteBuffer output;
    private final int pthreshold = 1024;
    private final int zthreshold = 896;
    private final int xthreshold = 512;
    protected int threshold;

    IOScheme() {
        String platform = System.getProperty("os.arch");
        if (platform.contains("x86") || platform.contains("amd")) {
            threshold = xthreshold;
        } else if (platform.contains("s390")) {
            threshold = zthreshold;
        } else if (platform.contains("ppc")) {
            threshold = pthreshold;
        } else {
            System.out.println(platform);
            System.err.println("Cannot determine architecture!");
            assert false;
        }

        input = ByteBuffer.allocateDirect(threshold);
        output = ByteBuffer.allocateDirect(threshold);
    }

    byte[] moveToInputIfSmall(byte[] buffer) {
        if (buffer.length > threshold) {
            return buffer;
        } else {
            input.position(0);
            input.limit(buffer.length);
            input.put(buffer, 0, buffer.length);
            return null;
        }
    }

    byte[] moveToOutputIfSmall(byte[] buffer) {
        if (buffer.length > threshold) {
            return buffer;
        } else {
            output.position(0);
            output.limit(buffer.length);
            output.put(buffer, 0, buffer.length);
            return null;
        }
    }

    void moveBackFromOutput(byte[] buffer, int size) {
        if (size <= threshold) {
            output.position(0);
            output.limit(size);
            output.get(buffer, 0, size);
        }
    }

}
