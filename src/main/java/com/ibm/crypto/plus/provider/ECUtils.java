/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

final class ECUtils {

    public static final int EC_SIZE_192 = 192;
    public static final int EC_SIZE_224 = 224;
    public static final int EC_SIZE_256 = 256;
    public static final int EC_SIZE_384 = 384;
    public static final int EC_SIZE_521 = 521;

    /**
     *
     * @param toString
     *            ECPoint to convert to String
     * @return ECPoint as a String
     */
    protected static String pointAsString(ECPoint toString) {
        StringBuffer buf = new StringBuffer("[");
        buf.append(toString.getAffineX().toString());
        buf.append(",");
        buf.append(toString.getAffineY().toString());
        buf.append("]");
        return buf.toString();
    }

    protected static String curveAsString(EllipticCurve toString) {
        StringBuffer buf = new StringBuffer();
        buf.append("#EllipticCurve ");
        buf.append(fieldAsString(toString.getField()));
        buf.append("\ta: " + toString.getA());
        buf.append("\tb: " + toString.getB());
        buf.append("#");
        return buf.toString();
    }

    protected static String fieldAsString(ECField toString) {
        StringBuffer buf = new StringBuffer();
        buf.append("{ECField \tsize: " + toString.getFieldSize());
        if (toString instanceof ECFieldFp) {
            ECFieldFp fp = (ECFieldFp) toString;
            buf.append("\tp: " + fp.getP());
        } else if (toString instanceof ECFieldF2m) {
            ECFieldF2m f2m = (ECFieldF2m) toString;
            buf.append("\tm: " + f2m.getM());
            buf.append("\treduction polynomial: " + f2m.getReductionPolynomial());
        }
        buf.append("}");
        return buf.toString();
    }


    public static boolean equals(ECParameterSpec spec1, ECParameterSpec spec2) {
        if (spec1 == spec2) {
            return true;
        }

        if (spec1 == null || spec2 == null) {
            return false;
        }
        return (spec1.getCofactor() == spec2.getCofactor()
                && spec1.getOrder().equals(spec2.getOrder())
                && spec1.getCurve().equals(spec2.getCurve())
                && spec1.getGenerator().equals(spec2.getGenerator()));
    }

    /**
     * utility function to debug
     */
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    static String bytesToHex(byte[] bytes) {
        if (bytes == null)
            return new String("-null-");
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String getCurvefromSize(int keySize) {
        switch (keySize) {
            case 112:
                return "secp112r1";
            case 128:
                return "secp128r1";
            case 160:
                return "secp160k1";
            case 192:
                return "secp192r1";
            case 224:
                return "secp224r1";
            case 239:
                return "X9.62 prime239v1";
            case 256:
                return "secp256r1";
            case 320:
                return "brainpoolP320r1";
            case 384:
                return "secp384r1";
            case 512:
                return "brainpoolP512r1";
            case 521:
                return "secp521r1";
            default:
                return null;
        }
    }

}
