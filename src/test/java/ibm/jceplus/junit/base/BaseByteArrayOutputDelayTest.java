/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import com.ibm.crypto.plus.provider.ock.ByteArrayOutputDelay;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * Test class for ByteArrayOutputDelay
 *
 */
public class BaseByteArrayOutputDelayTest extends BaseTestPublicMethodsToMakeNonPublic {

    private static byte[] TEST_DATA = new byte[1024];

    static {
        for (int i = 0; i < TEST_DATA.length; ++i) {
            TEST_DATA[i] = (byte) (i % 16);
        }

    }

    private static int TEST_COUNT = 0;

    @Test
    public void testInputSizeNotMultipleOfDelay() throws IOException {
        testByteArrayOutputDelay(16, 11, TEST_DATA); // test left overs
    }

    @Test
    public void testDelaySameSizeAsInput() throws IOException {
        testByteArrayOutputDelay(1024, 1024, TEST_DATA); // test one shot
    }

    @Test
    public void testDelayLargerThanInput() throws IOException {
        testByteArrayOutputDelay(4096, 1, TEST_DATA); // test buffer larger than data
    }

    @Test
    public void testRandom() throws IOException {
        testRandom(20);
    }

    @Test
    public void testDifferentDelayWritingByteAtATime() throws IOException {
        for (int bufferSize = 0; bufferSize < 17; ++bufferSize) {
            testByteArrayOutputDelay(bufferSize, 1, TEST_DATA);
        }

    }

    private void testRandom(int iterations) throws IOException {
        System.out.println("Running " + iterations + " random iterations");
        Random random = new SecureRandom();

        for (int i = 0; i < iterations; ++i) {

            int dataSize = random.nextInt(1048576);
            byte[] testData = new byte[dataSize];
            random.nextBytes(testData);

            int chopSize = random.nextInt(4095) + 1; // Generate a random between 1 and 4096.
            int delayByte = random.nextInt(dataSize);
            delayByte = delayByte % ByteArrayOutputDelay.MAX_BYTE_DELAY;

            testByteArrayOutputDelay(delayByte, chopSize, testData);
        }

    }

    /**
     * Test using a single byte of input data. Test with no delay Test with 1 byte
     * delay Test with 2 byte delay
     * 
     * @throws IOException
     */
    @Test
    public void testSingleByte() throws IOException {
        byte[] oneByte = {(byte) 255};
        testByteArrayOutputDelay(0, 1, oneByte); // no buffer
        testByteArrayOutputDelay(1, 1, oneByte);
        testByteArrayOutputDelay(2, 1, oneByte);

    }

    /**
     * Test with a negative byte delay
     * 
     * @throws IOException
     */
    @Test
    public void testIllegalByteDelay() throws IOException {
        byte[] oneByte = {(byte) 255};
        try {
            testByteArrayOutputDelay(-1, 1, oneByte);
            throw new RuntimeException("Expected IllegalArgumentException NOT received");
        } catch (IllegalArgumentException e) {
            System.out.println("Expected IllegalArgumentException received");
        }
    }

    /**
     * Construct a ByteArrayOutputDelay of delayByte size. Write the next chopsize
     * number of bytes to the ByteArrayOutputDelay Verify that the byte array
     * returned from write is correctly delayed.
     * 
     * @param delayByte - number of bytes to delay byte array by
     * @param chopSize  - number of bytes of input data to write at a time
     * @param testData  - data test with
     * @throws IOException
     */
    private void testByteArrayOutputDelay(int delayByte, int chopSize, byte[] testData)
            throws IOException {
        System.out.println("Test bufferSize: " + delayByte + " chopSize: " + chopSize
                + " Total length of input data: " + testData.length);
        TEST_COUNT += 1;
        if (chopSize < 1) {
            throw new IllegalArgumentException(
                    "chopSize must be greater than zero; given: " + chopSize);
        }
        ByteArrayOutputStream allOutput = new ByteArrayOutputStream(testData.length);

        ByteArrayOutputDelay keeper = new ByteArrayOutputDelay(delayByte);
        int totalByteCountFedIn = 0;
        for (int i = 0; (totalByteCountFedIn + chopSize) <= testData.length; i += chopSize) {
            totalByteCountFedIn += chopSize;
            // System.out.println("totalByteCountFedIn=" + totalByteCountFedIn);
            byte[] outputData = keeper.write(testData, i, chopSize);

            if (totalByteCountFedIn <= keeper.getByteDelay()) {
                // make sure nothing comes back before buffer full
                if (ByteArrayOutputDelay.EMPTY_BYTE_ARRAY != outputData) {
                    throw new RuntimeException("Received data before buffer full size="
                            + keeper.getByteDelay() + " index: " + i);
                } else {
                    System.out.print("0");
                }
            } else {
                int testMatchSize = (totalByteCountFedIn - keeper.getByteDelay()) % chopSize;
                if ((totalByteCountFedIn - chopSize) >= keeper.getByteDelay()) { // if keeper was full before this feed
                    testMatchSize = chopSize;
                }
                int startingMatchOffset = Math
                        .max((totalByteCountFedIn - chopSize - keeper.getByteDelay()), 0);
                byte[] testMatch = Arrays.copyOfRange(testData, startingMatchOffset,
                        startingMatchOffset + testMatchSize);
                if (!Compare(testMatch, outputData)) {
                    throw new RuntimeException(
                            "Overflow mismatch: expected: " + testData[i - keeper.getByteDelay()]
                                    + " received=" + outputData[0] + " index: " + i);
                } else {
                    System.out.print(".");
                }
            }

            allOutput.write(outputData);
            // System.out.println("allOutput size: " + allOutput.size() + " array size: " +
            // allOutput.toByteArray().length);
        }
        // Feed any remaining data
        int leftOverSize = testData.length - totalByteCountFedIn;
        if (leftOverSize > 0) {
            // System.out.println("Feeding remaining data size=" + leftOverSize);
            byte[] outputData = keeper.write(testData, testData.length - leftOverSize,
                    leftOverSize);
            allOutput.write(outputData);

        }

        byte[] outputData = keeper.flush();
        allOutput.write(outputData);

        System.out.println("");
        if (!((Arrays.equals(allOutput.toByteArray(), testData)))) {
            Compare(allOutput.toByteArray(), testData);
            throw new RuntimeException("Total output mismatch");
        }
        System.out.println("***************Keeper size: " + keeper.getByteDelay()
                + " done******************\n");
    }

    private static boolean Compare(byte[] a, byte[] b) {
        int z = -1;
        if (a.length != b.length) {
            System.out
                    .println(" DIFFERENT LENGTH a length: " + a.length + " b length: " + b.length);
            System.out.println();
            return false;
        } else {
            for (z = a.length - 1; z > 0; z--) {
                if (a[z] != b[z]) {
                    System.out.println(" DIFFERENT at index: " + z + " a:" + a[z] + " b:" + b[z]);
                    System.out.println();
                    return false;
                }
            }
        }
        if (z == 0) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isMethodMeantToBePublicAndExplicitlyCallableByUsers(Method method) {
        return true;
    }
}
