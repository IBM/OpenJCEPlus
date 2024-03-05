/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;
import sun.security.util.KnownOIDs;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

class CurveUtil {
    public enum CURVE {
        X25519, X448, FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192, Ed25519, Ed448
    }

    private static HashMap<CURVE, Integer> publicCurveSizes = new HashMap<CURVE, Integer>(); // key sizes of curves in bytes
    private static HashMap<Integer, CURVE> sizesToPublicCurves = new HashMap<Integer, CURVE>(); // reverse of above
    private static HashMap<CURVE, Integer> privateCurveSizes = new HashMap<CURVE, Integer>(); // key sizes of curves in bytes
    private static HashMap<Integer, CURVE> sizesToPrivateCurves = new HashMap<Integer, CURVE>(); // reverse of above
    private static HashMap<Integer, CURVE> sizesToCurves = new HashMap<Integer, CURVE>(); // maps the total key size (I think?)
                                                                                          // to algorithm (used in constructor)
    static {
        publicCurveSizes.put(CURVE.X25519, 32);
        publicCurveSizes.put(CURVE.X448, 56);
        publicCurveSizes.put(CURVE.FFDHE2048, 557);
        publicCurveSizes.put(CURVE.FFDHE3072, 813);
        publicCurveSizes.put(CURVE.FFDHE4096, 1069);
        publicCurveSizes.put(CURVE.FFDHE6144, 1581);
        publicCurveSizes.put(CURVE.FFDHE8192, 2093);
        publicCurveSizes.put(CURVE.Ed25519, 32);
        publicCurveSizes.put(CURVE.Ed448, 57);

        for (Map.Entry<CURVE, Integer> entry : publicCurveSizes.entrySet())
            sizesToPublicCurves.put(entry.getValue(), entry.getKey());

        privateCurveSizes.put(CURVE.X25519, 48);
        privateCurveSizes.put(CURVE.X448, 72);
        privateCurveSizes.put(CURVE.FFDHE2048, 327);
        privateCurveSizes.put(CURVE.FFDHE3072, 461);
        privateCurveSizes.put(CURVE.FFDHE4096, 595);
        privateCurveSizes.put(CURVE.FFDHE6144, 857);
        privateCurveSizes.put(CURVE.FFDHE8192, 1117);
        privateCurveSizes.put(CURVE.Ed25519, 32);
        privateCurveSizes.put(CURVE.Ed448, 57);

        for (Map.Entry<CURVE, Integer> entry : privateCurveSizes.entrySet())
            sizesToPrivateCurves.put(entry.getValue(), entry.getKey());

        sizesToCurves.put(255, CURVE.X25519);
        sizesToCurves.put(448, CURVE.X448);
        sizesToCurves.put(2048, CURVE.FFDHE2048); // this is my assumption
        sizesToCurves.put(3072, CURVE.FFDHE3072); // this is my assumption
        sizesToCurves.put(4096, CURVE.FFDHE4096); // this is my assumption
        sizesToCurves.put(6144, CURVE.FFDHE6144); // this is my assumption
        sizesToCurves.put(8192, CURVE.FFDHE8192); // this is my assumption
    }

    public static int getPublicCurveSize(CURVE curve) throws InvalidParameterException {
        if (!publicCurveSizes.containsKey(curve))
            throw new InvalidParameterException("Curve (" + curve + ") is not supported");
        return publicCurveSizes.get(curve);
    }

    public static int getPrivateCurveSize(CURVE curve) throws InvalidParameterException {
        if (!privateCurveSizes.containsKey(curve))
            throw new InvalidParameterException("Curve (" + curve + ") is not supported");
        return privateCurveSizes.get(curve);
    }

    public static CURVE getPublicCurveOfSize(int size) throws InvalidParameterException {
        if (!sizesToPublicCurves.containsKey(size))
            throw new InvalidParameterException(
                    "Public key size (" + size + ") does not correspond to a supported curve");
        return sizesToPublicCurves.get(size);
    }

    public static CURVE getCurveOfSize(int size) throws InvalidParameterException {
        if (!sizesToCurves.containsKey(size))
            throw new InvalidParameterException(
                    "Key size (" + size + ") does not correspond to a supported curve");
        return sizesToCurves.get(size);
    }

    /**
     * Returns the curve type based on the provided ObjectID and size,
     * which only has to be present if trying to identify an FFDHE curve.
     *
     * @param oid
     * @param size
     * @return curveType
     * @throws InvalidParameterException
     */
    public static CurveUtil.CURVE getCurve(ObjectIdentifier oid, Integer size)
            throws InvalidParameterException {
        if (oid == null)
            throw new InvalidParameterException();
        switch (oid.toString()) {
            case "1.3.101.110":
                return CurveUtil.CURVE.X25519;
            case "1.3.101.111":
                return CurveUtil.CURVE.X448;
            case "1.3.101.112":
                return CurveUtil.CURVE.Ed25519;
            case "1.3.101.113":
                return CurveUtil.CURVE.Ed448;
            case "1.2.840.113549.1.3.1":
                if (size == null)
                    throw new InvalidParameterException("Received oid: " + oid + " (size is " + size + ")");
                switch (size) {
                    case 2048:
                        return CurveUtil.CURVE.FFDHE2048;
                    case 3072:
                        return CurveUtil.CURVE.FFDHE3072;
                    case 4096:
                        return CurveUtil.CURVE.FFDHE4096;
                    case 6144:
                        return CurveUtil.CURVE.FFDHE6144;
                    case 8192:
                        return CurveUtil.CURVE.FFDHE8192;
                }
        }
        throw new InvalidParameterException("Received oid: " + oid + " (size is " + size + ")");
    }

    /**
     * Returns the curve type based on the provided curve name.
     *
     * @param curveName
     * @return curveType
     * @throws InvalidParameterException
     */
    public static CURVE getCurve(String curveName)
            throws InvalidParameterException {
        if (curveName == null)
            throw new InvalidParameterException();
        switch (curveName.toUpperCase()) {
            case "X25519":
                return CURVE.X25519;
            case "X448":
                return CURVE.X448;
            case "ED25519":
                return CURVE.Ed25519;
            case "ED448":
                return CURVE.Ed448;
            case "FFDHE2048":
                return CurveUtil.CURVE.FFDHE2048;
            case "FFDHE3072":
                return CurveUtil.CURVE.FFDHE3072;
            case "FFDHE4096":
                return CurveUtil.CURVE.FFDHE4096;
            case "FFDHE6144":
                return CurveUtil.CURVE.FFDHE6144;
            case "FFDHE8192":
                return CurveUtil.CURVE.FFDHE8192;
            default:
                throw new InvalidParameterException("Curve not supported: " + curveName);
        }
    }

    /**
     * Gets the AlgorithmID correlating to the input curve name
     * 
     * @param curveName
     * @return algId
     * @throws IOException
     */
    public static AlgorithmId getAlgId(String curveName) throws IOException {
        return getAlgId(getCurve(curveName));
    }

    /**
     * Gets the AlgorithmID correlating to the input curve type
     * 
     * @param curve
     * @return algId
     * @throws IOException
     */
    public static AlgorithmId getAlgId(CurveUtil.CURVE curve) throws IOException {
        switch (curve) {
            case Ed25519:
                return new AlgorithmId(ObjectIdentifier.of(KnownOIDs.Ed25519));
            case Ed448:
                return new AlgorithmId(ObjectIdentifier.of(KnownOIDs.Ed448));
            case X25519:
                return new AlgorithmId(ObjectIdentifier.of(KnownOIDs.X25519));
            case X448:
                return new AlgorithmId(ObjectIdentifier.of(KnownOIDs.X448));
            case FFDHE2048:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE3072:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE4096:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE6144:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
            case FFDHE8192:
                return new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"));
        }
        throw new IOException("The current curve is not supported");
    }

    /**
     * Checks whether a curve is of XEC algorithm or not
     * 
     * @param curve
     * @return boolean
     * @throws IOException
     */
    public static boolean isXEC(CURVE curve) throws IOException {
        return curve.name().contains("XEC");
    }

    /** Checks whether a curve is of Ed algorithm or not
     *
     * @param curve
     * @return boolean
     * @throws IOException
     */
    public static boolean isEd(CURVE curve) throws IOException {
        return curve.name().contains("Ed");
    }

    /**
     * Checks whether a curve is of FFDHE algorithm or not
     * 
     * @param curve
     * @return boolean
     * @throws IOException
     */
    public static boolean isFFDHE(CURVE curve) throws IOException {
        return curve.name().contains("FFDHE");
    }

    /**
     * Checks if the oid is valid, throws an exception otherwise
     *
     * @param oid
     * @throws IOException
     */
    public static void checkOid(ObjectIdentifier oid) throws IOException {
        if (oid == null || (!oid.toString().equals("1.3.101.110")
                /* X25519 */ && !oid.toString().equals("1.3.101.111") /* X448 */)
                && !oid.toString().equals("1.3.101.112") /* Ed25519 */
                && !oid.toString().equals("1.3.101.113") /* Ed448 */
                && !oid.toString().equals("1.2.840.113549.1.3.1") /* FFDHE */)
            throw new IOException(
                    "This curve does not seem to be an X25519, X448, Ed25519, Ed448 or FFDHE curve");
    }

    
}
