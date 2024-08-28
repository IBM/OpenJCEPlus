/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Objects;

final class ECUtils {

    public static final int EC_SIZE_192 = 192;
    public static final int EC_SIZE_224 = 224;
    public static final int EC_SIZE_256 = 256;
    public static final int EC_SIZE_384 = 384;
    public static final int EC_SIZE_521 = 521;

    // /**
    // * Negate an ECPoint over the curve
    // *
    // * @param toNegate
    // * @param curve
    // * @return
    // */
    // protected static ECPoint negate(ECPoint toNegate, EllipticCurve curve){
    // ECFieldFp field = (ECFieldFp)curve.getField();
    // BigInteger p = field.getP();
    // return new ECPoint(toNegate.getAffineX(),
    // toNegate.getAffineY().negate().mod(p));
    // }
    //
    // /**
    // * Compute P - Q over the curve
    // *
    // * @param P minuend; point on curve
    // * @param Q subtrahend; point on curve
    // * @param curve
    // * @return null if result is infinity or zero/origin; otherwise return
    // difference
    // */
    // protected static ECPoint subtract(ECPoint P, ECPoint Q, EllipticCurve
    // curve) {
    // ECPoint t = negate(Q, curve);
    // t = add(P, t, curve);
    // return t;
    // }
    //
    // /**
    // * Compute P + Q over the curve
    // *
    // * @param P point on curve
    // * @param Q point on curve
    // * @param curve
    // * @return null if result is infinity or zero/origin; otherwise return sum
    // */
    // protected static ECPoint add(ECPoint P, ECPoint Q, EllipticCurve curve) {
    //
    // // based on p 306/307 of William Stallings "Cryptography and Network
    // Security"
    //
    // ECFieldFp ecfield = (ECFieldFp)curve.getField();
    // BigInteger p = ecfield.getP();
    // BigInteger lambda = new BigInteger("0");
    //
    // /************* this needs to be thought about *****************/
    // if ( Q == null /* infinite */) {
    // return P;
    // } else if (P == null /*infinite*/){
    // return Q;
    // }
    //
    // ECPoint negQ = negate(Q, curve);
    //
    // if ( P.equals(negQ)){ /*this gives the orgin, O; should it be null as
    // well?*/
    // return null;
    // }
    // /************* this needs to be thought about *****************/
    //
    // // if this and Q are distinct points
    // else if ( !P.equals(Q)) {
    //
    // // lambda = (yQ - yP)/(xQ - xP) mod p
    // BigInteger s = Q.getAffineY().subtract(P.getAffineY());
    // BigInteger t = Q.getAffineX().subtract(P.getAffineX()).modInverse(p);
    // lambda = s.multiply(t).mod(p);
    // }
    //
    // // if this and Q are the same, provided Yp != 0 this is doing doubling
    // else if (P.equals(Q) && P.getAffineY().compareTo(BigInteger.ZERO)!=0){
    //
    // // lambda = (3xP^2 + a)/2yP mod p
    // BigInteger s = P.getAffineX().modPow(new BigInteger("2"), p).multiply(new
    // BigInteger("3")).add(curve.getA());
    // BigInteger t = P.getAffineY().multiply(new
    // BigInteger("2")).modInverse(p);
    // lambda = s.multiply(t).mod(p);
    // } else {
    // return null;
    // }
    //
    // //xR = (lambda^2 - xP - xQ) mod p
    // BigInteger xR = lambda.modPow(new BigInteger("2"),
    // p).subtract(P.getAffineX()).subtract(Q.getAffineX()).mod(p);
    //
    // //yR = (lambda(xP - xR) - yP) mod p
    // BigInteger yR =
    // lambda.multiply(P.getAffineX().subtract(xR)).subtract(P.getAffineY()).mod(p);
    // return new ECPoint(xR, yR);
    // }
    //
    // /**
    // * Compute k*P over the curve
    // *
    // * @param k scalar
    // * @param P point on curve
    // * @param curve
    // * @return
    // */
    // protected static ECPoint multiplyIteratively(BigInteger k, ECPoint P,
    // EllipticCurve curve) {
    // ECPoint t = new ECPoint(P.getAffineX(), P.getAffineY());
    // ECPoint s = new ECPoint(P.getAffineX(), P.getAffineY());
    // BigInteger k1 = k.subtract(BigInteger.ONE);
    // for (BigInteger i = BigInteger.ZERO; i.compareTo(k1)<0;
    // i=i.add(BigInteger.ONE)) {
    // s = add(t, s, curve);
    //// System.out.println(" i = " + i.toString() + " s = " + s.toString());
    // }
    // return s;
    // }
    //
    // /**
    // * Compute k*P over the curve (optimized)
    // */
    // protected static ECPoint multiply(BigInteger k, ECPoint P, EllipticCurve
    // curve){
    // ECPoint inner;
    // ECPoint previous;
    // ECPoint res;
    //
    // BigInteger two = new BigInteger("2");
    //
    // res = P;
    // inner = P;
    // previous = P;
    //
    //
    // if(k.compareTo(two) != 1){
    // return multiplyIteratively(k,P,curve);
    // }
    //
    // String bitString = k.toString(2);
    // char[] bits = bitString.toCharArray();
    // int kLength = bitString.length();
    // //System.out.println(kLength);
    //
    // for(int i = 0; i<kLength; i++){
    // //System.err.print(bitString.charAt(i));
    // if(i == 0){
    // // just double
    // //previous = ECUtils.add(previous, previous, curve);
    // continue;
    // }
    // if(bits[i] == '0'){
    // previous = ECUtils.add(previous, previous, curve);
    // } else { // '1'
    // previous = ECUtils.add(P, ECUtils.add(previous, previous, curve), curve);
    // }
    // }
    //
    // res = previous;
    //
    // return res;
    // }
    //
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

    /**
     * Same implementation from sun.security.util.ECUtil in semeru jdk21
     */
    /**
     * 
     * Check an ECPrivateKey to make sure the scalar value is within the
     * range of the order [1, n-1].
     *
     * @param prv the private key to be checked.
     *
     * @return the private key that was evaluated.
     *
     * @throws InvalidKeyException if the key's scalar value is not within
     *      the range 1 <= x < n where n is the order of the generator.
     */
    protected static java.security.interfaces.ECPrivateKey checkPrivateKey(java.security.interfaces.ECPrivateKey prv)
            throws InvalidKeyException {
        // The private key itself cannot be null, but if the private
        // key doesn't divulge the parameters or more importantly the S value
        // (possibly because it lives on a provider that prevents release
        // of those values, e.g. HSM), then we cannot perform the check and
        // will allow the operation to proceed.
        Objects.requireNonNull(prv, "Private key must be non-null");
        ECParameterSpec spec = prv.getParams();
        if (spec != null) {
            BigInteger order = spec.getOrder();
            BigInteger sVal = prv.getS();

            if (order != null && sVal != null) {
                if (sVal.compareTo(BigInteger.ZERO) <= 0 ||
                        sVal.compareTo(order) >= 0) {
                    throw new InvalidKeyException("The private key must be " +
                            "within the range [1, n - 1]");
                }
            }
        }

        return prv;
    }
}
