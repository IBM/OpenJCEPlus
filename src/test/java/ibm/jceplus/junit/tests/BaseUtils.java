/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

public class BaseUtils {

    /**
     * Converts a byte array to a hex string.   
     * @param input the byte array to convert
     * @return the hex string
     */
    public static String bytesToHex(byte[] input) {
        if (input == null) {
            return "<NULL>";
        }

        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < input.length; ++i) {
            sb.append(String.format("%02x", input[i] & 0xff));
        }

        return sb.toString();
    }    

}
