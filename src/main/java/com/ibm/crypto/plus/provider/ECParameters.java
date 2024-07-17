/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidParameterSpecException;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ECKeySizeParameterSpec;
import sun.security.util.ObjectIdentifier;

/**
 * This class implements encoding and decoding of Elliptic Curve parameters
 * as specified in RFC 3279.
 *
 * ASN.1 from RFC 3279 follows. Note that X9.62 (2005) has added some additional
 * options.
 *
 * <pre>
 *    EcpkParameters ::= CHOICE {
 *      ecParameters  ECParameters,
 *      namedCurve    OBJECT IDENTIFIER,
 *      implicitlyCA  NULL }
 *
 *    ECParameters ::= SEQUENCE {
 *       version   ECPVer,          -- version is always 1
 *       fieldID   FieldID,         -- identifies the finite field over
 *                                  -- which the curve is defined
 *       curve     Curve,           -- coefficients a and b of the
 *                                  -- elliptic curve
 *       base      ECPoint,         -- specifies the base point P
 *                                  -- on the elliptic curve
 *       order     INTEGER,         -- the order n of the base point
 *       cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n
 *       }
 *
 *    ECPVer ::= INTEGER {ecpVer1(1)}
 *
 *    FieldID ::= SEQUENCE {
 *       fieldType   OBJECT IDENTIFIER,
 *       parameters  ANY DEFINED BY fieldType
 *       }
 *
 *    Curve ::= SEQUENCE {
 *       a         FieldElement,
 *       b         FieldElement,
 *       seed      BIT STRING OPTIONAL }
 *
 *    FieldElement ::= OCTET STRING
 *
 *    ECPoint  ::= OCTET STRING      -- Elliptic curve point
 *
 * </pre>
 *
 */

/**
 *
 */
public final class ECParameters extends AlgorithmParametersSpi {

    protected int cofactor;
    protected EllipticCurve curve;
    protected ECPoint generator;
    protected BigInteger order;

    /*
     * The parameters these AlgorithmParameters object represents.
     * Currently, it is always an instance of NamedCurve.
     */
    private NamedCurve namedCurve;

    public ECParameters() {
        super();
    }

    // used by ECPublicKeyImpl and ECPrivateKeyImpl
    static AlgorithmParameters getAlgorithmParameters(OpenJCEPlusProvider provider,
            ECParameterSpec spec) throws InvalidKeyException {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", provider);
            params.init(spec);
            return params;
        } catch (GeneralSecurityException e) {
            //throw new InvalidParameterSpecException("Unsupported parameter specification: " + e);
            throw new InvalidKeyException("EC parameters error", e);
        }
    }



    // AlgorithmParameterSpi methods

    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {

        internalInit(paramSpec);


    }

    protected void internalInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {

        if (paramSpec == null) {
            throw new InvalidParameterSpecException("paramSpec must not be null");
        }

        if (paramSpec instanceof NamedCurve) {
            namedCurve = (NamedCurve) paramSpec;
            return;
        }

        if (paramSpec instanceof ECParameterSpec) {
            namedCurve = CurveDB.lookup((ECParameterSpec) paramSpec);
        } else if (paramSpec instanceof ECGenParameterSpec) {
            String name = ((ECGenParameterSpec) paramSpec).getName();
            namedCurve = CurveDB.lookup(name);
        } else if (paramSpec instanceof ECKeySizeParameterSpec) {
            int keySize = ((ECKeySizeParameterSpec) paramSpec).getKeySize();
            namedCurve = CurveDB.lookup(keySize);
        } else {
            throw new InvalidParameterSpecException(
                    "Only ECParameterSpec and ECGenParameterSpec supported");
        }

        if (namedCurve == null) {
            throw new InvalidParameterSpecException("Not a supported curve: " + paramSpec);
        }


    }


    protected void engineInit(byte[] params) throws IOException {
        DerValue encodedParams = new DerValue(params);
        if (encodedParams.tag == DerValue.tag_ObjectId) {
            ObjectIdentifier oid = encodedParams.getOID();
            NamedCurve spec = CurveDB.lookup(oid.toString());
            if (spec == null) {
                throw new IOException("Unknown named curve: " + oid);
            }

            namedCurve = spec;

            return;
        }

        throw new IOException("Only named ECParameters supported");


    }

    protected void engineInit(byte[] params, String decodingMethod) throws IOException {
        engineInit(params);
    }


    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> spec)
            throws InvalidParameterSpecException {

        if (spec.isAssignableFrom(ECParameterSpec.class)) {
            return spec.cast(namedCurve);
        }

        if (spec.isAssignableFrom(ECGenParameterSpec.class)) {
            // Ensure the name is the Object ID
            String name = namedCurve.getObjectId();
            return spec.cast(new ECGenParameterSpec(name));
        }


        throw new InvalidParameterSpecException(
                "Only ECParameterSpec and ECGenParameterSpec supported");
    }

    protected byte[] engineGetEncoded() throws IOException {
        return namedCurve.getEncoded();
    }

    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        return engineGetEncoded();
    }



    protected String engineToString() {
        if (namedCurve == null) {
            return "Not initialized";
        }

        return namedCurve.toString();
    }

    // COPIED FROM PKCS60 ECParameters.java
    // Used by SunPKCS11 and SunJSSE.
    static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
        // NOTE: The encoding of ECPoint is a "byte array". (See RFC 3279)
        // Therefore, there is no "der encoding" within this method.
        int fieldSizeInBits = (curve.getField().getFieldSize());
        // get field size in bytes (rounding up)
        int n = (fieldSizeInBits + 7) >> 3;
        byte[] xb = trimZeroes(point.getAffineX().toByteArray());
        byte[] yb = trimZeroes(point.getAffineY().toByteArray());
        if ((xb.length > n) || (yb.length > n)) {
            throw new ProviderException("Point coordinates do not match field size");
        }
        byte[] b = new byte[1 + (n << 1)];
        b[0] = 4; // uncompressed
        System.arraycopy(xb, 0, b, n - xb.length + 1, xb.length);
        System.arraycopy(yb, 0, b, b.length - yb.length, yb.length);
        return b;
    }

    // COPIED FROM PKCS60 ECParameters.java
    // Used by SunPKCS11 and SunJSSE.
    static ECPoint decodePoint(byte[] data, EllipticCurve curve) throws IOException {
        // NOTE: The encoding of an ECPoint is a "byte array". (See RFC 3279)
        // Therefore, there is no "der decoding" within this method.
        if ((data.length == 0) || (data[0] != 4)) {
            throw new IOException("Only uncompressed point format supported");
        }
        int n = (curve.getField().getFieldSize() + 7) >> 3;
        if (data.length != (n * 2) + 1) {
            throw new IOException("Point does not match field size");
        }
        byte[] xb = new byte[n];
        byte[] yb = new byte[n];
        System.arraycopy(data, 1, xb, 0, n);
        System.arraycopy(data, n + 1, yb, 0, n);
        return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
    }

    // COPIED FROM PKCS60 ECParameters.java
    // Trims the leading (most significant) zeroes from the result.
    static byte[] trimZeroes(byte[] b) {
        int i = 0;
        while ((i < b.length - 1) && (b[i] == 0)) {
            i++;
        }
        if (i == 0) {
            return b; // There were no leading zeroes.
        }
        byte[] t = new byte[b.length - i]; // Allocate new array minus space for
                                           // leading zeroes
        System.arraycopy(b, i, t, 0, t.length);
        return t;
    }

    // Curve ::= SEQUENCE {
    // a FieldElement,
    // b FieldElement,
    // seed BIT STRING OPTIONAL }
    //
    // FieldElement ::= OCTET STRING

    private static DerValue encodeEllipticCurve(EllipticCurve curve) throws IOException {

        byte[] aByteArray = trimZeroes(curve.getA().toByteArray());
        byte[] bByteArray = trimZeroes(curve.getB().toByteArray());
        byte[] seed = curve.getSeed(); // May be null
        DerOutputStream out = new DerOutputStream();
        out.putOctetString(aByteArray);
        out.putOctetString(bByteArray);
        if (seed != null) {
            out.putBitString(seed);
        }
        // Observe that the DerValues above are the
        // "data" of the DerValue with the SEQUENCE TAG
        DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());
        return val;

    }

    // Curve ::= SEQUENCE {
    // a FieldElement,
    // b FieldElement,
    // seed BIT STRING OPTIONAL }
    //
    // FieldElement ::= OCTET STRING

    private static EllipticCurve decodeEllipticCurve(DerValue encodedEllipticCurve, ECField ecField)
            throws IOException {

        try {
            if (encodedEllipticCurve.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Not a SEQUENCE");
            }
            DerInputStream data = encodedEllipticCurve.getData();

            byte[] aByteArray = data.getOctetString();
            BigInteger a = new BigInteger(1, aByteArray);
            byte[] bByteArray = data.getOctetString();
            BigInteger b = new BigInteger(1, bByteArray);
            byte[] seed = null;
            if (data.available() != 0) {
                seed = data.getBitString();
            }

            EllipticCurve ellipticCurve = null;
            if (seed == null) {
                ellipticCurve = new EllipticCurve(ecField, a, b);
            } else {
                ellipticCurve = new EllipticCurve(ecField, a, b, seed);
            }
            return ellipticCurve;
        } catch (IOException e) {
            throw new IOException("Exception in decodeEllipticCurve(): " + e);
        }
    }

    // Currently this class encodes/decodes only "elliptic curve prime finite
    // fields". (e.g. ECFieldFp)
    // The methods encodePrimeFieldType() and decodePrimeFieldType() provide
    // this
    // capability.
    // The encoding/decoding of "elliptic curve characteristic 2 finite fields"
    // (e.g. ECFieldF2m) is not yet supported.

    // FieldID ::= SEQUENCE {
    // fieldType OBJECT IDENTIFIER,
    // parameters ANY DEFINED BY fieldType }
    //
    // Root OID for identifying prime field types
    // id-fieldType OBJECT IDENTIFIER ::= { ansi-X9-62 fieldType(1) }
    // OID identifying prime field types
    // prime-field OBJECT IDENTIFIER ::= { id-fieldType 1 }
    //
    // Parameters for prime field
    // Prime-p ::= INTEGER -- Field size p (p in bits)

    private static DerValue encodePrimeFieldType(ECFieldFp fieldID) throws IOException {

        try {
            String primeFieldType_data = "1.2.840.10045.1.1";
            ObjectIdentifier primeFieldTypeOID = ObjectIdentifier.of(primeFieldType_data);

            BigInteger p = fieldID.getP();

            DerOutputStream out = new DerOutputStream();
            out.putOID(primeFieldTypeOID);
            out.putInteger(p);
            // Observe that the DerValues above are the
            // "data" of the DerValue with the SEQUENCE TAG
            DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());
            return val;

        } catch (IOException e) {
            throw new IOException("Exception in encodePrimeFieldType(): " + e);
        }
    }

    private static ECFieldFp decodePrimeFieldType(DerValue encodedPrimeFieldType)
            throws IOException {

        String primeFieldType_data = "1.2.840.10045.1.1";
        ObjectIdentifier primeFieldTypeOID = ObjectIdentifier.of(primeFieldType_data);

        try {
            if (encodedPrimeFieldType.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Not a SEQUENCE");
            }
            DerInputStream data = encodedPrimeFieldType.getData();

            ObjectIdentifier decodedPrimeFieldTypeOID = data.getOID();
            if (!(decodedPrimeFieldTypeOID.equals(primeFieldTypeOID))) {
                throw new IOException("Incorrect OID encountered during decodePrimeFieldType.");
            }
            BigInteger p = data.getBigInteger();

            ECFieldFp myFieldID = new ECFieldFp(p);
            return myFieldID;
        } catch (IOException e) {
            throw new IOException("Exception in decodePrimeFieldType(): " + e);
        }
    }

    // ECParameters ::= SEQUENCE {
    // version ECPVer, -- version is always 1
    // fieldID FieldID, -- identifies the finite field over
    // -- which the curve is defined
    // curve Curve, -- coefficients a and b of the
    // -- elliptic curve
    // base ECPoint, -- specifies the base point P
    // -- on the elliptic curve
    // order INTEGER, -- the order n of the base point
    // cofactor INTEGER OPTIONAL -- The integer h = #E(Fq)/n
    // }
    //
    // ECPVer ::= INTEGER {ecpVer1(1)}
    //
    // Curve ::= SEQUENCE {
    // a FieldElement,
    // b FieldElement,
    // seed BIT STRING OPTIONAL }
    //
    // FieldElement ::= OCTET STRING
    //
    // ECPoint ::= OCTET STRING

    private byte[] encodeECParameters() throws IOException {

        try {
            EllipticCurve curve = this.curve;
            ECPoint ecPoint = this.generator;
            BigInteger order = this.order;
            int cofactor = this.cofactor;

            // Create an ECParameterSpec object from the individual values above
            ECParameterSpec params = new ECParameterSpec(curve, ecPoint, order, cofactor);

            // If the ECParameterSpec object just created represents a well
            // known named
            // curve
            // then obtain an instance of ECNamedCurve which represents that
            // named curve.
            ECNamedCurve myCurve = getNamedCurve(params);
            // myCurve = null; - //Uncomment this line to test custom curve
            // parameters.
            if (myCurve != null) {
                // This ECParameters object represents a well known named curve.
                // Therefore, this ECParameters object can be encoded as a
                // single OID value.

                return myCurve.getEncoded(); // return the encoding of that
                                             // NamedCurve.
            }
            // System.out.println ("creating custom custom curve parameters");
            ECField ecField = curve.getField();

            DerOutputStream out = new DerOutputStream();
            out.putInteger(1); // version 1

            if (ecField instanceof ECFieldFp) {
                // The PrimeFieldType SEQUENCE is a single DerValue.
                // The Tag of this DerValue is "SEQUENCE".
                // The elements of the SEQUENCE are emdedded within the
                // data of this single DerValue.
                DerValue encodedPrimeFieldType = encodePrimeFieldType((ECFieldFp) ecField);
                out.putDerValue(encodedPrimeFieldType);
            } else {
                throw new IOException(
                        "ECFieldF2m encountered in encodeECParameters().  ECFieldF2m is not currently supported.");
            }

            // The EllipticCurve SEQUENCE is a single DerValue.
            // The Tag of this DerValue is "SEQUENCE".
            // The elements of the SEQUENCE are embedded within the
            // data of this single DerValue.
            DerValue encodedEllipticCurve = encodeEllipticCurve(curve);
            out.putDerValue(encodedEllipticCurve);

            byte[] encodedECPoint = encodePoint(ecPoint, curve);
            out.putOctetString(encodedECPoint);

            out.putInteger(order);

            out.putInteger(cofactor);

            DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());

            byte[] encodedECParameters = val.toByteArray();
            return encodedECParameters;
        } catch (IOException e) {
            throw new IOException("Exception in encodeECParameters(): " + e);
        }
    }

    static byte[] encodeECParameters(ECParameterSpec params) throws IOException {
        // System.out.println ("params=" + params);
        try {
            EllipticCurve curve = params.getCurve();
            ECPoint ecPoint = params.getGenerator();
            BigInteger order = params.getOrder();
            int cofactor = params.getCofactor();

            // Create an ECParameterSpec object from the individual values above
            // ECParameterSpec params = new ECParameterSpec(curve, ecPoint,
            // order, cofactor);

            // If the ECParameterSpec object just created represents a well
            // known named
            // curve
            // then obtain an instance of ECNamedCurve which represents that
            // named curve.
            ECNamedCurve myCurve = getNamedCurve(params);
            // Force it go through fully specifying parameters
            // myCurve = null; //Uncomment this line to test custom curve
            // parameters.
            if (myCurve != null) {
                // This ECParameters object represents a well known named curve.
                // Therefore, this ECParameters object can be encoded as a
                // single OID value.
                // System.out.println ("Known Named curve" + myCurve.getName());
                return myCurve.getEncoded(); // return the encoding of that
                                             // NamedCurve.
            }

            ECField ecField = curve.getField();

            DerOutputStream out = new DerOutputStream();
            out.putInteger(1); // version 1

            if (ecField instanceof ECFieldFp) {
                // The PrimeFieldType SEQUENCE is a single DerValue.
                // The Tag of this DerValue is "SEQUENCE".
                // The elements of the SEQUENCE are emdedded within the
                // data of this single DerValue.
                DerValue encodedPrimeFieldType = encodePrimeFieldType((ECFieldFp) ecField);
                out.putDerValue(encodedPrimeFieldType);
            } else {
                throw new IOException(
                        "ECFieldF2m encountered in encodeECParameters().  ECFieldF2m is not currently supported.");
            }

            // The EllipticCurve SEQUENCE is a single DerValue.
            // The Tag of this DerValue is "SEQUENCE".
            // The elements of the SEQUENCE are embedded within the
            // data of this single DerValue.
            DerValue encodedEllipticCurve = encodeEllipticCurve(curve);
            out.putDerValue(encodedEllipticCurve);

            byte[] encodedECPoint = encodePoint(ecPoint, curve);
            out.putOctetString(encodedECPoint);

            out.putInteger(order);

            out.putInteger(cofactor);

            DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());

            byte[] encodedECParameters = val.toByteArray();
            return encodedECParameters;
        } catch (IOException e) {
            throw new IOException("Exception in encodeECParameters(): " + e);
        }
    }

    // ECParameters ::= SEQUENCE {
    // version ECPVer, -- version is always 1
    // fieldID FieldID, -- identifies the finite field over
    // -- which the curve is defined
    // curve Curve, -- coefficients a and b of the
    // -- elliptic curve
    // base ECPoint, -- specifies the base point P
    // -- on the elliptic curve
    // order INTEGER, -- the order n of the base point
    // cofactor INTEGER OPTIONAL -- The integer h = #E(Fq)/n
    // }
    //
    // ECPVer ::= INTEGER {ecpVer1(1)}
    //
    // Curve ::= SEQUENCE {
    // a FieldElement,
    // b FieldElement,
    // seed BIT STRING OPTIONAL }
    //
    // FieldElement ::= OCTET STRING
    //
    // ECPoint ::= OCTET STRING

    private static ECParameterSpec decodeECParameters(byte[] encodedECParameters)
            throws IOException {
        boolean haveCofactor = false;
        try {
            DerInputStream in = new DerInputStream(encodedECParameters);
            DerValue derValue = in.getDerValue();
            if (derValue.getTag() != DerValue.tag_Sequence) {
                if (derValue.getTag() == DerValue.tag_ObjectId) {
                    // we have an OID, so we need to produce an ECParameterSpec
                    // from it
                    String oid = (derValue.getOID()).toString();
                    return ECNamedCurve.getECParameterSpec(oid);
                } else {
                    // System.err.println("Tag: " + derValue.getTag());
                    throw new IOException("Not a SEQUENCE or an OID");
                }
            }
            DerInputStream data = derValue.getData();
            
            //Get version
            data.getInteger();

            // byte[] encodedFieldID = data.getSequence();
            DerValue encodedFieldID = data.getDerValue(); // Use getDerValue(),
                                                          // NOT getSequence()
                                                          // to get a SEQUENCE
                                                          // Then pick off the
                                                          // SEQUENCE tag,
                                                          // then pick off the
                                                          // sequence elements
            ECFieldFp fieldID = decodePrimeFieldType(encodedFieldID);

            // byte[] encodedEllipticCurve = data.getSequence();
            DerValue encodedEllipticCurve = data.getDerValue(); // Use
                                                                // getDerValue(),
                                                                // NOT
                                                                // getSequence()
                                                                // to get a
                                                                // SEQUENCE
                                                                // Then pick off
                                                                // the SEQUENCE
                                                                // tag, then
                                                                // pick off the
                                                                // sequence
                                                                // elements
            EllipticCurve curve = decodeEllipticCurve(encodedEllipticCurve, fieldID);

            byte[] encodedECPoint = data.getOctetString();
            ECPoint ecPoint = decodePoint(encodedECPoint, curve);

            BigInteger order = data.getBigInteger();

            int cofactor = 0;
            if (data.available() != 0) {
                haveCofactor = true;
                cofactor = data.getInteger();
            }

            // Build an ECParameterSpec object from the pieces

            ECParameterSpec ecParameterSpec = null;
            if (haveCofactor == true) {
                ecParameterSpec = new ECParameterSpec(curve, ecPoint, order, cofactor);
            } else {
                ecParameterSpec = new ECParameterSpec(curve, ecPoint, order, 0);
            }

            return ecParameterSpec;
        } catch (IOException e) {
            throw new IOException("Exception in decodeECParameters(): " + e);
        }
    }

    // If the ECParameterSpec passed in matches a known named curve, then return
    // an
    // instance
    // of ECNamedCurve for that named curve. Otherwise, return "null".
    static ECNamedCurve getNamedCurve(ECParameterSpec params) {

        try {

            // Get a copy of the nameMap from ECNamedCurve.
            // The nameMap is a LinkedHashMap where the Key is a ECNamedCurve
            // name string,
            // and
            // the value is an ECParameterSpec of the associated ECNamedCurve
            Map<String, ECParameterSpec> nameMap = ECNamedCurve.getNameMap();
            Set<Entry<String, ECParameterSpec>> myEntrySet = nameMap.entrySet();

            // Scan the entries of the nameMap for an ECParameterSpec value that
            // matches the
            // one passed in.
            for (Iterator<Entry<String, ECParameterSpec>> myIter = myEntrySet.iterator(); myIter.hasNext();) {
                Entry<String, ECParameterSpec> myMapEntry = myIter.next();
                String curveNameFromNameMap = myMapEntry.getKey();
                ECParameterSpec ecParameterSpecFromNameMap = myMapEntry
                        .getValue();

                // Does ecParameterSpecFromNameMap match the one passed in?
                // The ECParameterSpec class does not define equals, so I'll
                // need to check all
                // the
                // components here.

                // Compare the EllipticCurve components
                BigInteger A1 = ecParameterSpecFromNameMap.getCurve().getA();
                BigInteger A2 = params.getCurve().getA();

                BigInteger B1 = ecParameterSpecFromNameMap.getCurve().getB();
                BigInteger B2 = params.getCurve().getB();

                int fieldSize1 = ecParameterSpecFromNameMap.getCurve().getField().getFieldSize();
                int fieldSize2 = params.getCurve().getField().getFieldSize();

                byte[] seedValue1 = ecParameterSpecFromNameMap.getCurve().getSeed();
                byte[] seedValue2 = params.getCurve().getSeed();

                if ((A1.equals(A2) == false) || (B1.equals(B2) == false)
                        || (fieldSize1 != fieldSize2)) {
                    continue;
                }

                // Compare the seed values from the EllipticCurve object
                // separately, since they
                // require a
                // bit more logic.
                // if seedValue1 == null and seedValue2 is null this looks good, do nothing.
                if ((seedValue1 == null) && (seedValue2 != null)) {
                    continue; // skip this named curve
                } else if ((seedValue1 != null) && (seedValue2 == null)) {
                    continue; // skip this named curve
                } else if ((seedValue1 != null) && (seedValue2 != null)) {
                    if (seedValue1.length != seedValue2.length) {
                        continue; // skip this named curve
                    } else {
                        // Compare the two seed values
                        boolean doTheyMatch = true;
                        for (int i = 0; i < seedValue1.length; i++) {
                            if (seedValue1[i] != seedValue2[i]) {
                                doTheyMatch = false;
                                break;
                            }
                        }
                        if (doTheyMatch == false) {
                            continue; // skip this named curve
                        }
                    }
                }

                if (ecParameterSpecFromNameMap.getGenerator()
                        .equals(params.getGenerator()) == false) {
                    continue;
                }

                if (ecParameterSpecFromNameMap.getOrder().equals(params.getOrder()) == false) {
                    continue;
                }

                if (ecParameterSpecFromNameMap.getCofactor() != params.getCofactor()) {
                    continue;
                }

                // ecParameterSpecFromNameMap MATCHES! Therefore, I also have
                // the associated
                // ECNamedCurve name string.
                // Create an instance of that ECNamedCurve and return it.
                ECNamedCurve myECNamedCurve = new ECNamedCurve(curveNameFromNameMap);
                return myECNamedCurve;

            }

            // No match was found in the nameMap. Return null.
            return null;

        } catch (Exception e) {
            return null; // Adding this statement to satisfy the compiler
        }
    }

    ///////////////////// UNIT TESTS FOR THIS CLASS BELOW
    ///////////////////// ////////////////////////

    /*
     * public static void main(String[] args) {
     * System.out.println("=================================================");
     * System.out.println("BEGIN doFieldIDTest()"); doFieldIDTest();
     * System.out.println("END   doFieldIDTest()");
     *
     * System.out.println("=================================================");
     * System.out.println("BEGIN doEllipticCurveTest()"); doEllipticCurveTest();
     * System.out.println("END   doEllipticCurveTest()");
     *
     * System.out.println("=================================================");
     * System.out.println("BEGIN doECPointTest()"); doECPointTest();
     * System.out.println("END   doECPointTest()");
     *
     * System.out.println("=================================================");
     * System.out.println("BEGIN doECParametersTest()"); doECParametersTest();
     * System.out.println("END   doECParametersTest()");
     *
     * System.out.println("=================================================");
     * }
     *
     *
     *
     * static void doFieldIDTest() { try { // Test Encoding/Decoding of FieldID
     * ECFieldFp myFieldID1 = new ECFieldFp( new BigInteger("127") ); DerValue
     * myEncodedFieldID = encodePrimeFieldType( myFieldID1 );
     *
     * ECFieldFp myFieldID2 = decodePrimeFieldType( myEncodedFieldID );
     *
     * BigInteger p1 = myFieldID1.getP(); BigInteger p2 = myFieldID2.getP();
     *
     * if ( p1.equals(p2) ) { System.out.println("FieldID testing SUCCEEDED!");
     * } else { System.out.println("FieldID testing FAILED!"); } } catch
     * (IOException e) {
     * System.out.println("Exception caught in doFieldIDTest():  " + e);
     * e.printStackTrace(); } }
     *
     *
     *
     * static void doEllipticCurveTest() { try { ECField myECField1 = new
     * ECFieldFp( new BigInteger( "137" ) ); EllipticCurve myEllipticCurve1 =
     * new EllipticCurve( myECField1, new BigInteger( "3" ), new BigInteger( "7"
     * ) );
     *
     * DerValue myEncodedEllipticCurve1 = encodeEllipticCurve( myEllipticCurve1
     * );
     *
     * EllipticCurve myEllipticCurve2 = decodeEllipticCurve(
     * myEncodedEllipticCurve1, myECField1);
     *
     * if ( myEllipticCurve1.equals(myEllipticCurve2) ) {
     * System.out.println("EllipticCurve test1 SUCCEEDED!"); } else {
     * System.out.println("EllipticCurve test1 FAILED!"); }
     *
     * // ---------------------------------
     *
     * byte[] seed = { 5, 26, 19, 44 };
     *
     * ECField myECField3 = new ECFieldFp( new BigInteger( "137" ) );
     * EllipticCurve myEllipticCurve3 = new EllipticCurve( myECField3, new
     * BigInteger( "3" ), new BigInteger( "7" ), seed );
     *
     * DerValue myEncodedEllipticCurve3 = encodeEllipticCurve( myEllipticCurve3
     * );
     *
     * EllipticCurve myEllipticCurve4 = decodeEllipticCurve(
     * myEncodedEllipticCurve3, myECField3);
     *
     * if ( myEllipticCurve3.equals(myEllipticCurve4) ) {
     * System.out.println("EllipticCurve test2 SUCCEEDED!"); } else {
     * System.out.println("EllipticCurve test2 FAILED!"); } } catch (IOException
     * e) { System.out.println("Exception caught in doEllipticCurveTest():  " +
     * e); e.printStackTrace(); } }
     *
     *
     *
     * static void doECPointTest() { try { ECPoint myECPoint1 = new ECPoint( new
     * BigInteger("7"), new BigInteger("11") );
     *
     * ECField myECField1 = new ECFieldFp( new BigInteger( "137" ) );
     * EllipticCurve myEllipticCurve1 = new EllipticCurve( myECField1, new
     * BigInteger( "3" ), new BigInteger( "7" ) );
     *
     * byte[] myEncodedECPoint1 = encodePoint( myECPoint1, myEllipticCurve1 );
     *
     * ECPoint myECPoint2 = decodePoint( myEncodedECPoint1, myEllipticCurve1 );
     *
     * if ( myECPoint1.equals(myECPoint2) ) {
     * System.out.println("ECPoint test1 SUCCEEDED!"); } else {
     * System.out.println("ECPoint test1 FAILED!"); }
     *
     * // ---------------------------------
     *
     * byte[] seed = { 5, 26, 19, 44 };
     *
     * ECPoint myECPoint3 = new ECPoint( new BigInteger("7"), new
     * BigInteger("11") );
     *
     * ECField myECField3 = new ECFieldFp( new BigInteger( "137" ) );
     * EllipticCurve myEllipticCurve3 = new EllipticCurve( myECField3, new
     * BigInteger( "3" ), new BigInteger( "7" ), seed);
     *
     * byte[] myEncodedECPoint3 = encodePoint( myECPoint3, myEllipticCurve3 );
     *
     * ECPoint myECPoint4 = decodePoint( myEncodedECPoint3, myEllipticCurve3 );
     *
     * if ( myECPoint3.equals(myECPoint4) ) {
     * System.out.println("ECPoint test2 SUCCEEDED!"); } else {
     * System.out.println("ECPoint test2 FAILED!"); } } catch (IOException e) {
     * System.out.println("Exception caught in doECPointTest():  " + e);
     * e.printStackTrace(); } }
     *
     *
     *
     * static void doECParametersTest() { try { byte[] seed = { 27, 2, 19, 64,
     * 13, 6 };
     *
     * boolean testSuccess = true;
     *
     * ECPoint myECPoint1 = new ECPoint( new BigInteger("7"), new
     * BigInteger("11") );
     *
     * ECField myECField1 = new ECFieldFp( new BigInteger( "137" ) );
     * EllipticCurve myEllipticCurve1 = new EllipticCurve( myECField1, new
     * BigInteger( "3" ), new BigInteger( "7" ), seed);
     *
     * ECParameterSpec myECParameterSpec1 = new ECParameterSpec(
     * myEllipticCurve1, myECPoint1, new BigInteger("5"), 13);
     *
     * ECParameters myECParameters = new ECParameters();
     * myECParameters.engineInit(myECParameterSpec1);
     *
     * byte[] myEncodedECParameters1 = myECParameters.encodeECParameters( );
     *
     * ECParameterSpec myECParameterSpec2 = decodeECParameters(
     * myEncodedECParameters1 );
     *
     * testSuccess = true;
     *
     * if ( myECParameterSpec1.getCofactor() != myECParameterSpec2.getCofactor()
     * ) { testSuccess = false; }
     *
     * if ( !(myECParameterSpec1.getCurve().equals(
     * myECParameterSpec2.getCurve() ) ) ) { testSuccess = false; }
     *
     * if ( !(myECParameterSpec1.getGenerator().equals(
     * myECParameterSpec2.getGenerator() ) ) ) { testSuccess = false; }
     *
     * if ( !(myECParameterSpec1.getOrder().equals(
     * myECParameterSpec2.getOrder() ) ) ) { testSuccess = false; }
     *
     * if ( testSuccess == true ) {
     * System.out.println("ECParameters test SUCCEEDED!"); } else {
     * System.out.println("ECParameters test FAILED!"); } } catch (IOException
     * e) { System.out.println("IOException caught in doECParametersTest():  " +
     * e); e.printStackTrace(); } catch (InvalidParameterSpecException e) {
     * System.out.
     * println("InvalidParameterSpecException caught in doECParametersTest():  "
     * + e); e.printStackTrace(); } }
     *
     *
     * // Converts a byte array to hex string for debugging public static String
     * toHexString(byte[] block) { StringBuffer buf = new StringBuffer(); char[]
     * hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B',
     * 'C', 'D', 'E', 'F' }; int len = block.length; int high = 0; int low = 0;
     *
     * for (int i = 0; i < len; i++) { if (i%16 == 0) buf.append('\n'); high =
     * ((block[i] & 0xf0) >> 4); low = (block[i] & 0x0f);
     * buf.append(hexChars[high]); buf.append(hexChars[low]); buf.append(' '); }
     *
     * return buf.toString(); }
     */

    ///////////////////// UNIT TESTS FOR THIS CLASS ABOVE
    ///////////////////// ////////////////////////////

}
