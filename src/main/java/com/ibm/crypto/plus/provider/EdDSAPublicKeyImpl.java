/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.CurveUtil.CURVE;
import com.ibm.crypto.plus.provider.ock.XECKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import sun.security.util.BitArray;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.X509Key;

final class EdDSAPublicKeyImpl extends X509Key implements EdECPublicKey {

    private static final long serialVersionUID = 1L;

    private transient EdECPoint point;
    private OpenJCEPlusProvider provider = null;
    private transient NamedParameterSpec paramSpec;
    private CURVE curve;

    private transient XECKey xecKey = null;

    private void setFieldsFromXeckey() throws Exception {
        byte[] keyArray = xecKey.getPublicKeyBytes();
        setKey(new BitArray(keyArray.length * 8, keyArray));

        this.paramSpec = new NamedParameterSpec(curve.name());

        byte msb = keyArray[keyArray.length - 1];
        keyArray[keyArray.length - 1] &= (byte) 0x7F;
        boolean xOdd = (msb & 0x80) != 0;
        reverseByteArray(keyArray);
        BigInteger y = new BigInteger(1, keyArray);
        this.point = new EdECPoint(xOdd, y);

    }

    /**
     * Make a XEC public key from its components
     *
     * @param provider
     * @param xecKey
     *            the internal XECKey object that is key will contain
     * @throws InvalidKeyException
     */
    EdDSAPublicKeyImpl(OpenJCEPlusProvider provider, XECKey xecKey,
            CURVE curve) throws InvalidKeyException {
        if (provider == null)
            throw new InvalidKeyException("provider cannot be null");
        if (xecKey == null)
            throw new InvalidKeyException("xecKey cannot be null");

        this.provider = provider;
        this.xecKey = xecKey;
        this.curve = curve;
        try {
            this.algid = CurveUtil.getAlgId(curve);
            setFieldsFromXeckey();
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create XEC public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

        //System.out.println("Pub Point = " + this.point);
    }


    EdDSAPublicKeyImpl(OpenJCEPlusProvider provider,
            NamedParameterSpec params, EdECPoint point)
            throws InvalidAlgorithmParameterException, InvalidParameterException, InvalidKeyException {

        if (provider == null)
            throw new InvalidKeyException("provider cannot be null");
        this.paramSpec = params;
        this.point = point;

        this.curve = CurveUtil.getEdCurve(params);

        try {
            this.algid = CurveUtil.getAlgId(this.curve);

            byte[] encodedPoint = point.getY().toByteArray();

            reverseByteArray(encodedPoint);

            // array may be too large or too small, depending on the value
            encodedPoint = Arrays.copyOf(encodedPoint,
                    CurveUtil.getCurveSize(this.curve));
            // set the high-order bit of the encoded point
            byte msb = (byte) (point.isXOdd() ? 0x80 : 0);

            encodedPoint[encodedPoint.length - 1] |= msb;
            setKey(new BitArray(encodedPoint.length * 8, encodedPoint));

            byte[] der = buildOCKPublicKeyBytes();
            byte[] alteredEncoded = alterEncodedPublicKey(der); // Alters encoded to fit GSKit, and sets params

            this.xecKey = XECKey.createPublicKey(provider.getOCKContext(), alteredEncoded, provider);

        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EdDSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

        checkLength(this.curve);
    }

    EdDSAPublicKeyImpl(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException {

        if (provider == null)
            throw new InvalidKeyException("provider cannot be null");
        this.provider = provider;

        decode(encoded);

        try {
            // construct the EdECPoint representation
            byte[] encodedPoint = getKey().toByteArray();

            byte msb = encodedPoint[encodedPoint.length - 1];
            encodedPoint[encodedPoint.length - 1] &= (byte) 0x7F;
            boolean xOdd = (msb & 0x80) != 0;
            reverseByteArray(encodedPoint);
            BigInteger y = new BigInteger(1, encodedPoint);
            this.point = new EdECPoint(xOdd, y);

            byte[] der = buildOCKPublicKeyBytes();
            this.xecKey = XECKey.createPublicKey(provider.getOCKContext(), der, provider);

        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EdDSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
        checkLength(this.curve);
    }


    /**
     * Takes a DER encoded key of the following format: SEQUENCE: [SEQUENCE[OID, NULL], BITSTRING]
     * Returns a similar DER with the first part of the sequence changed to:
     * SEQUENCE[OID] (sequence of 1 element)
     * It's weird, no idea why it is this way but that's what GSKit/OpenSSL accepts
     *
     * The function also sets the params field
     *
     * @param encoded
     * @return
     * @throws IOException
     */
    private byte[] alterEncodedPublicKey(byte[] encoded) throws IOException {

        DerInputStream in = new DerInputStream(encoded);
        DerValue[] inputValue = in.getSequence(2);
        DerOutputStream outStream = new DerOutputStream();

        // Extract info from OID
        DerOutputStream outputOIDSequence = new DerOutputStream();
        processOIDSequence(inputValue[0].toDerInputStream(),
                outputOIDSequence);

        // Write OID on new outstream
        outStream.write(DerValue.tag_Sequence, outputOIDSequence.toByteArray());

        if (inputValue.length > 1) {
            byte[] publicKey = inputValue[1].getBitString();
            outStream.putBitString(publicKey);
        } else {
            throw new IOException("DER sequence does not contain public key");
        }

        DerOutputStream asn1Key = new DerOutputStream();
        asn1Key.write(DerValue.tag_Sequence, outStream);

        return asn1Key.toByteArray();
    }

    void checkLength(CURVE curve) throws InvalidKeyException {
        if (CurveUtil.getCurveSize(curve) * 8 != getKey().length()) {
            throw new InvalidKeyException("key length must be "
                    + CurveUtil.getCurveSize(curve));
        }
    }

    public byte[] getEncodedPoint() {
        return getKey().toByteArray();
    }

    @Override
    public EdECPoint getPoint() {
        return point;
    }

    @Override
    public NamedParameterSpec getParams() {
        return paramSpec;
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
    }

    XECKey getOCKKey() {
        return this.xecKey;
    }

    /**
     * Takes a the OID Sequence part of a DER encoded key
     * Retrieves the curve type from that DER and sets the parameter
     * Retrieves and returns the OID
     * If output stream is present, copy all the retrieved data into it
     *
     * @param oidInputStream
     * @return objectIdentifer
     * @throws IOException
     */
    private ObjectIdentifier processOIDSequence(DerInputStream oidInputStream,
            DerOutputStream outStream) throws IOException {
        ObjectIdentifier oid = oidInputStream.getOID();
        CurveUtil.checkOid(oid);
        this.curve = CurveUtil.getCurve(oid, null);

        if (outStream != null) {
            outStream.putOID(oid);
        }

        this.paramSpec = new NamedParameterSpec(this.curve.name());
        return oid;
    }


    /**
     * Builds DER from public key to be used to build EVP_PKEY in GSKit
     * DER form: SEQUENCE: [SEQUENCE[OID], BITSTRING]
     *
     * @return
     * @throws IOException
     */
    private byte[] buildOCKPublicKeyBytes() throws IOException {
        DerOutputStream mainSeq = new DerOutputStream();
        DerOutputStream outStream = new DerOutputStream();
        DerOutputStream oidSeq = new DerOutputStream();

        // Sequence containing only one element: the OID
        oidSeq.putOID(this.algid.getOID());

        // Forming main sequence
        mainSeq.write(DerValue.tag_Sequence, oidSeq.toByteArray());
        mainSeq.putBitString(getKey().toByteArray());
        outStream.write(DerValue.tag_Sequence, mainSeq);
        return outStream.toByteArray();
    }

    /**
     * Returns the DER-encoded form of the key as a byte array.
     */
    public byte[] getEncoded() {
        try {
            if (encodedKey == null) {
                encodedKey = alterEncodedPublicKey(super.getEncoded()); //Make is match was was sent to GSKIT
            }
            return encodedKey.clone();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void decode(byte[] encoded) throws InvalidKeyException {
        try {
            this.encodedKey = encoded.clone();
            DerInputStream inp = new DerInputStream(encoded);
            DerValue[] values = inp.getSequence(2);

            if (values.length < 2)
                throw new InvalidKeyException("Key does not appear to be a EdDSA key");

            DerInputStream seq = values[0].toDerInputStream();
            processOIDSequence(seq, null);
            this.algid = CurveUtil.getAlgId(this.curve);

            byte[] keyArray = values[1].getBitString();
            setKey(new BitArray(keyArray.length * 8, keyArray));
        } catch (Exception e) {
            throw new InvalidKeyException("Key does not appear to be a EdDSA key");
        }
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PUBLIC, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    }

    /**
     * Reverses a byte array (in place)
     *
     * @param arr
     * @return
     * @throws IOException
     */
    private static void reverseByteArray(byte[] arr) throws IOException {
        for (int i = 0; i < arr.length / 2; i++) {
            byte temp = arr[i];
            arr[i] = arr[arr.length - 1 - i];
            arr[arr.length - 1 - i] = temp;
        }
    }

    private static void swap(byte[] arr, int i, int j) {
        byte tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

}
