/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.security.internal.spec;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

public class NamedParameterSpec implements AlgorithmParameterSpec {



    public enum CURVE {
        X25519, X448, FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192, Ed25519, Ed448
    }

    private CURVE curve;
    private String curveName;
    // It keeps external passed parameter of java documented class.
    // So, the internal NamedParameterSpec acts as a wrapper class for this instance variable.
    private java.security.spec.NamedParameterSpec externalParameter = null;

    private static HashMap<CURVE, Integer> publicCurveSizes = new HashMap<CURVE, Integer>(); // key sizes of curves in bytes
    private static HashMap<Integer, CURVE> sizesToPrivateCurves = new HashMap<Integer, CURVE>(); // reverse of above
    private static HashMap<CURVE, Integer> privateCurveSizes = new HashMap<CURVE, Integer>(); // key sizes of curves in bytes
    private static HashMap<Integer, CURVE> sizesToPublicCurves = new HashMap<Integer, CURVE>(); // reverse of above
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
     *
     * @param spec input argument of type AlgorithmParameterSpec
     * @return An instance of internal NamedParameterSpec
     * @throws InvalidParameterException
     */
    public static ibm.security.internal.spec.NamedParameterSpec getInternalNamedParameterSpec(
            AlgorithmParameterSpec spec) throws InvalidParameterException {

        ibm.security.internal.spec.NamedParameterSpec iSpec = null;

        if (spec instanceof ibm.security.internal.spec.NamedParameterSpec) {
            iSpec = (ibm.security.internal.spec.NamedParameterSpec) spec;

        } else if (spec instanceof java.security.spec.NamedParameterSpec) {
            iSpec = new ibm.security.internal.spec.NamedParameterSpec(
                    ((java.security.spec.NamedParameterSpec) spec).getName());
        } else {
            throw new InvalidParameterException("Invalid Parameter: " + spec);
        }
        return iSpec;
    }

    /**
     * Constructs a NamedParameterSpec from the curve name
     * @param curveName
     * @exception InvalidParameterException
     */
    public NamedParameterSpec(String curveName) throws InvalidParameterException {
        try {
            curve = CURVE.valueOf(checkCurveName(curveName));
        } catch (Exception e) {
            throw new InvalidParameterException(curveName + " is not supported");
        }
        this.curveName = curve.name();
        this.externalParameter = new java.security.spec.NamedParameterSpec(this.curveName);
    }

    /**
     * Checks the input curve name to convert it to the appropriate curve name
     * @param curveName The name of the input curve to be checked
     * @return The converted curve name
     */
    private String checkCurveName(String curveName) {
        String cnUp = curveName.toUpperCase();
        switch (cnUp) {
            case "ED25519":
                return "Ed25519";
            case "ED448":
                return "Ed448";
            case "X25519":
            case "X448":
            case "FFDHE2048":
            case "FFDHE3072":
            case "FFDHE4096":
            case "FFDHE6144":
            case "FFDHE8192":
                return cnUp;
            default:
                return curveName;
        }
    }

    /**
     * Constructs keySize NamedParameterSpec from the keySize
     * @param keySize
     * @exception InvalidParameterException
     */
    public NamedParameterSpec(int keySize) throws InvalidParameterException {
        this.curve = getCurveOfSize(keySize);
        this.curveName = curve.toString();
        this.externalParameter = new java.security.spec.NamedParameterSpec(this.curveName);
    }

    /**
     * Constructs a NamedParameterSpec from the curve enum
     * @param curve
     * @exception InvalidParameterException
     */
    public NamedParameterSpec(CURVE curve) throws InvalidParameterException {
        this.curve = curve;
        this.curveName = curve.toString();
        this.externalParameter = new java.security.spec.NamedParameterSpec(this.curveName);
    }

    /**
     * Returns the curve's name
     * @return curveName
     */
    public String getName() {
        return curveName;
    }

    /**
     * Returns the curve's type (enum)
     * @return curve
     */
    public CURVE getCurve() {
        return curve;
    }

    public java.security.spec.NamedParameterSpec getExternalParameter() {
        return this.externalParameter;
    }
}
