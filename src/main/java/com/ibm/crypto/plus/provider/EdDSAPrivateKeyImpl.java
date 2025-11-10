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
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

final class EdDSAPrivateKeyImpl extends PKCS8Key implements EdECPrivateKey {

    private static final long serialVersionUID = 1L;

    private static final byte TAG_PARAMETERS_ATTRS = 0x00;
    private OpenJCEPlusProvider provider = null;
    private transient byte[] h;
    private transient NamedParameterSpec paramSpec;
    private CURVE curve;
    private Exception exception = null; // In case an exception happened and the API did
    // not allow us to throw it, we throw it at the end

    private transient XECKey xecKey = null;

    private void setFieldsFromXeckey() throws Exception {
        if (this.key == null) {
            this.key = extractPrivateKeyFromOCK(xecKey.getPrivateKeyBytes()); // Extract key from GSKit and sets params
            DerInputStream derStream = new DerInputStream(this.key);
            this.h = derStream.getOctetString();
            this.algid = CurveUtil.getAlgId(this.curve);
        }
    }


    /**
     * Construct a key from an internal XECKey.
     *
     * @param provider
     * @param xecKey
     */
    EdDSAPrivateKeyImpl(OpenJCEPlusProvider provider, XECKey xecKey)
            throws InvalidKeyException {
        if (provider == null)
            throw new InvalidKeyException("provider cannot be null");
        if (xecKey == null)
            throw new InvalidKeyException("xecKey cannot be null");
        this.xecKey = xecKey;
        this.provider = provider;
        try {
            setFieldsFromXeckey();
        } catch (Exception e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    EdDSAPrivateKeyImpl(OpenJCEPlusProvider provider,
            NamedParameterSpec params, byte[] h)
            throws InvalidAlgorithmParameterException, InvalidParameterException, InvalidKeyException {

        this.provider = provider;
        this.paramSpec = params;

        this.curve = CurveUtil.getEdCurve(params);

        try {
            this.algid = CurveUtil.getAlgId(this.curve);

            if (h != null) {
                this.h = h.clone();
                DerValue val = new DerValue(DerValue.tag_OctetString, h);
                try {
                    this.key = val.toByteArray();
                } finally {
                    val.clear();
                }
            }

            if (this.key == null) {
                int keySize = CurveUtil.getCurveSize(curve);
                this.xecKey = XECKey.generateKeyPair(provider.getOCKContext(),
                        this.curve.ordinal(), keySize, provider);
            } else {
                this.algid = CurveUtil.getAlgId(this.curve);
                byte[] der = buildOCKPrivateKeyBytes();
                int encodingSize = CurveUtil.getDEREncodingSize(curve);
                this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), der,
                        encodingSize, provider);
            }
        } catch (Exception exception) {
            InvalidParameterException ike = new InvalidParameterException(
                    "Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
        checkLength(this.curve);
    }

    EdDSAPrivateKeyImpl(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException, IOException {
        super(encoded);
        this.provider = provider;
        try {
            byte[] alteredEncoded = processEncodedPrivateKey(encoded); // Sets params, key, and algid, and alters encoded
            // to fit with GSKit and sets params

            checkLength(this.curve);
            int encodingSize = CurveUtil.getDEREncodingSize(curve);
            this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), alteredEncoded,
                    encodingSize, provider);

        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    void checkLength(CURVE curve) throws InvalidKeyException {

        if (CurveUtil.getCurveSize(curve) != this.h.length) {
            throw new InvalidKeyException(
                    "key length is " + this.h.length + ", key length must be "
                            + CurveUtil.getCurveSize(curve));
        }
    }


    /**
     * Takes a DER encoded key of the following format: SEQUENCE: [version (INTEGER),
     * OID (OID is inside a sequence of 1 element), private key (OCTET STRING)]
     * Returns a similar DER with the last part of the sequence changed to:
     * OCTETSTRING[OCTETSTRING] (Octet string of an octet string which is the private key)
     * It's weird, no idea why it is this way but that's what GSKIT/OpenSSL accepts
     *
     * The function also sets the params field, algid, and key
     *
     * @param encoded
     * @return
     * @throws IOException
     */
    private byte[] processEncodedPrivateKey(byte[] encoded) throws IOException {
        DerInputStream in = new DerInputStream(encoded);
        DerValue[] inputValue = in.getSequence(3);
        DerOutputStream outStream = new DerOutputStream();

        // Copy version from input DER to new DER
        BigInteger version = inputValue[0].getBigInteger();
        outStream.putInteger(version);

        // Copy OID
        ObjectIdentifier oid = null;
        if (inputValue.length < 3)
            throw new IOException("This curve does not seem to be a valid EdDSA curve");

        if (inputValue[1].getTag() == DerValue.tag_Sequence) {
            DerInputStream oidInputStream = inputValue[1].toDerInputStream();
            DerOutputStream outputOIDSequence = new DerOutputStream();
            oid = processOIDSequence(oidInputStream, outputOIDSequence);
            this.algid = new AlgorithmId(oid);
            outStream.write(DerValue.tag_Sequence, outputOIDSequence.toByteArray());
        } else
            throw new IOException("Unexpected non sequence while parsing private key bytes");

        // Read, convert, then write private key
        this.key = inputValue[2].getOctetString(); // Get octet string
        DerInputStream derStream = new DerInputStream(this.key);
        this.h = derStream.getOctetString();

        outStream.putOctetString(this.key);

        DerOutputStream asn1Key = new DerOutputStream();
        asn1Key.write(DerValue.tag_Sequence, outStream);

        return asn1Key.toByteArray();
    }

    /**
     * Takes a the OID Sequence part of a DER encoded key
     * Retrieves the curve type from that DER and sets the parameter
     * Retrieves and returns the OID
     * If output stream is present, put the OID to the output stream
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

        this.paramSpec = new NamedParameterSpec(curve.name());
        return oid;
    }

    /**
     * Extract and return the private key bytes from the output DER returned from GSKit.
     * The EdDSA privateKeyBytes format is SEQUENCE: [INTEGER (version), SEQUENCE[OID],
     * OCTET STRING[OCTET STRING(private key)]
     *
     * The function also sets the params field
     *
     * @param privateKeyBytes
     * @return
     * @throws IOException
     */
    private byte[] extractPrivateKeyFromOCK(byte[] privateKeyBytes) throws IOException {
        DerInputStream in = new DerInputStream(privateKeyBytes);
        DerValue[] inputValue = in.getSequence(3);
        // Retrieve OID and make sure its an EdDSA curve
        DerInputStream derInputStream = null;
        if (inputValue.length > 1) {
            derInputStream = inputValue[1].getData();
            try {
                processOIDSequence(derInputStream, null);
            } catch (Exception ex) {
                throw new IOException(
                        "This curve does not seem to be an EdDSA curve or correct OID", ex);
            }
        }

        // Private key is in the form of an octet string stored inside another octet string
        byte[] privData = null;
        if (inputValue.length > 2) {
            privData = inputValue[2].getOctetString();
            return privData;
        }
        return null;
    }

    /**
     * Builds DER from private key to be used to build EVP_PKEY in GSKit
     * DER form: SEQUENCE: SEQUENCE: [INTEGER (version), SEQUENCE[OID], OCTET STRING[OCTET STRING] (private key)
     *
     * @return
     * @throws IOException
     */
    private byte[] buildOCKPrivateKeyBytes() throws IOException {
        DerOutputStream mainSeq = new DerOutputStream();

        // Add first BigInteger (always 0 for EdDSA)
        mainSeq.putInteger(0);

        // Adding OID
        DerOutputStream oidSeq = new DerOutputStream();
        oidSeq.putOID(this.algid.getOID());
        mainSeq.write(DerValue.tag_Sequence, oidSeq.toByteArray());

        // Adding Key
        mainSeq.putOctetString(this.key);

        // Wrapping up in a sequence
        DerOutputStream outStream = new DerOutputStream();
        outStream.write(DerValue.tag_Sequence, mainSeq);
        return outStream.toByteArray();
    }

    XECKey getOCKKey() {
        return this.xecKey;
    }

    @Override
    public NamedParameterSpec getParams() {
        return this.paramSpec;
    }

    @Override
    public Optional<byte[]> getBytes() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return Optional.of(this.h);
    }

    @Override
    public AlgorithmId getAlgorithmId() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return super.getAlgorithmId();
    }

    @Override
    public byte[] getEncoded() {
        byte[] results = null;
        try {
            results = this.xecKey.getPrivateKeyBytes();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return results;
    }

    @Override
    public String getAlgorithm() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }

        return "EdDSA";
    }

    @java.io.Serial
    protected Object writeReplace() throws java.io.ObjectStreamException {
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    } 
}

