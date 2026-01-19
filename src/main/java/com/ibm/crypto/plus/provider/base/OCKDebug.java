/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

public class OCKDebug {
    /**
     * utility function to debug
     */
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    //    public static String bytesToHex(byte[] bytes) {
    //        if (bytes == null)
    //            return new String("-null-");
    //        char[] hexChars = new char[bytes.length * 2];
    //        for (int j = 0; j < bytes.length; j++) {
    //            int v = bytes[j] & 0xFF;
    //            hexChars[j * 2] = hexArray[v >>> 4];
    //            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    //        }
    //        return new String(hexChars);
    //    }
    //        //Useful for printing long Strings.
    //    public static String bytesToHex(byte[] bytes, int firstNbytes, int lastNbytes ) {
    //        if (bytes == null)
    //            return new String("-null-");
    //        char[] hexChars = new char[bytes.length * 2];
    //                if (bytes.length < 2*(firstNbytes + lastNbytes)) {
    //                   return bytesToHex(bytes);
    //                }
    //        for (int j = 0; j < bytes.length; j++) {
    //            int v = bytes[j] & 0xFF;
    //            hexChars[j * 2] = hexArray[v >>> 4];
    //            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    //        }
    //              String retValue = String.valueOf(bytes.length) + " " + new String(hexChars, 0, (2*firstNbytes))  + "..." +
    //            new String(hexChars,(hexChars.length - (2*lastNbytes)), (2*lastNbytes));
    //        return retValue;
    //    }
    //
    //    public static void Msg (String debPrefix, String methodName, 
    //            String msg) {
    //        //System.err.println (debPrefix + " " + methodName + " " + "ThreadId=" + Thread.currentThread().getId() + " " + msg );
    //    }    
    //    
    //    public static void Msg (String debPrefix, String methodName, 
    //            int msg) {
    //        //System.err.println (debPrefix + " " + methodName + " " + "ThreadId=" + Thread.currentThread().getId() + " " + msg );
    //    }
    //    
    //    public static void Msg (String debPrefix, String methodName, 
    //            long msg) {
    //        //System.err.println (debPrefix + " " + methodName + " " + "ThreadId=" + Thread.currentThread().getId() + " " + msg );
    //    }
    //    
    //    public static void Msg (String debPrefix, String methodName, 
    //            byte []msg) {
    //        int length = (msg != null) ? msg.length : 0;
    //        System.err.println (debPrefix + " " + methodName + " ThreadId=" + Thread.currentThread().getId() + " " + " msg.length :" + length + " " + bytesToHex(msg) );
    //    }
    //    public static void Msg (String debPrefix, String methodName, 
    //            boolean msg) {
    //        //System.err.println (debPrefix + " " + methodName + " " + "ThreadId=" + Thread.currentThread().getId() + " " + msg );
    //    }
    //    public static void Msg (String debPrefix, String methodName, 
    //            String msgPrefix, byte []msg) {
    //    int length = (msg != null) ? msg.length : 0;
    //    System.err.println (debPrefix + " " + methodName + " ThreadId=" + Thread.currentThread().getId() + " " + " msg.length :" + length + " " + bytesToHex(msg) );
    //
    //    }
    //    
    //    public static void Msg (String debPrefix, String methodName, 
    //            Object msg) {
    //        //System.err.println (debPrefix + " " + methodName + " " + "ThreadId=" + Thread.currentThread().getId() + " " + msg);
    //    }
    //    public static void Msg (String debPrefix, String methodName, String msgPrefix, 
    //            Object msg) {
    //        //System.err.println (debPrefix + " " + methodName + " " + "ThreadId=" + Thread.currentThread().getId() + " " + msgPrefix + " " + msg);
    //    }
}
