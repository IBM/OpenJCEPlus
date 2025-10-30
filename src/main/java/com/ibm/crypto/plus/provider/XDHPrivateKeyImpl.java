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
import java.io.OutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

final class XDHPrivateKeyImpl extends PKCS8Key implements XECPrivateKey, Serializable, Destroyable {

    // Field serialVersionUID per tag [SERIALIZATION] in DesignNotes.txt
    private static final long serialVersionUID = 6034044314589513430L;

    private OpenJCEPlusProvider provider = null;
    private transient Optional<byte[]> scalar;
    private transient NamedParameterSpec params;
    private CURVE curve;
    private byte[] k; // The raw key bytes, without OctetString or DER encoded
    BigInteger bi1; // parameter used in FFDHE
    BigInteger bi2; // parameter used in FFDHE
    BigInteger bi3; // parameter used in FFDHE
    private Exception exception = null; // In case an exception happened and the API did
    // not allow us to throw it, we throw it at the end

    private static final byte TAG_PARAMETERS_ATTRS = 0x00;

    private transient boolean destroyed = false;
    private transient XECKey xecKey = null;

    private void setFieldsFromXeckey() throws Exception {
        if (k == null) {
            k = extractPrivateKeyFromOCK(xecKey.getPrivateKeyBytes()); // Extract key from GSKit and sets params
            setPKCS8KeyByte(k);
            this.scalar = Optional.of(k);
            this.algid = CurveUtil.getAlgId(this.params.getName());
        }
    }

    /**
     * Construct a key from an internal XECKey.
     *
     * @param provider
     * @param xecKey
     */
    public XDHPrivateKeyImpl(OpenJCEPlusProvider provider, XECKey xecKey)
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
            throw new InvalidKeyException(e.getMessage(), e);
        }
    }

    /**
     * Construct a key from a DER encoded key.
     *
     * @param provider
     * @param encoded
     */
    public XDHPrivateKeyImpl(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException {
        this.provider = provider;
        try {
            byte[] alteredEncoded = processEncodedPrivateKey(encoded); // Sets params, key, and algid, and alters encoded
            // to fit with GSKit and sets params
            int encodingSize = CurveUtil.getDEREncodingSize(curve);
            this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), alteredEncoded, encodingSize, provider);
            this.scalar = Optional.of(k);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Construct a key from a its scalar parameter.
     *
     * @param provider
     * @param scalar
     * @param params   must be of type NamedParameterSpec
     */
    public XDHPrivateKeyImpl(OpenJCEPlusProvider provider, AlgorithmParameterSpec params,
            Optional<byte[]> scalar) throws InvalidAlgorithmParameterException, InvalidParameterException {

        if (provider == null) {
            throw new InvalidParameterException("provider must not be null");
        }

        if (params instanceof NamedParameterSpec) {
            this.params = (NamedParameterSpec) params;
        } else {
            throw new InvalidParameterException("Invalid Parameters: " + params);
        }

        this.curve = CurveUtil.getXCurve(this.params);

        try {
            if (CurveUtil.isFFDHE(this.curve))
                throw new InvalidParameterException("FFDHE algorithms are not suppoerted");
        } catch (Exception e) {
            throw new InvalidParameterException(e.getMessage());
        }
        // TODO: figure out how to build FFDHE curves from paramspec

        this.provider = provider;
        this.scalar = scalar;
        if (scalar != null)
            k = scalar.get();
        try {
            if (k == null) {
                int keySize = CurveUtil.getCurveSize(curve);
                this.xecKey = XECKey.generateKeyPair(provider.getOCKContext(), this.curve.ordinal(), keySize, provider);
            } else {
                this.algid = CurveUtil.getAlgId(this.params.getName());
                byte[] der = buildOCKPrivateKeyBytes();
                int encodingSize = CurveUtil.getDEREncodingSize(curve);
                this.xecKey = XECKey.createPrivateKey(provider.getOCKContext(), der, encodingSize, provider);
            }
            setPKCS8KeyByte(k);
        } catch (Exception exception) {
            InvalidParameterException ike = new InvalidParameterException(
                    "Failed to create XEC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

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

        // Add first BigInteger (always 0 for XEC/FFDHE)
        mainSeq.putInteger(0);

        // Adding OID
        DerOutputStream oidSeq = new DerOutputStream();
        oidSeq.putOID(this.algid.getOID());
        mainSeq.write(DerValue.tag_Sequence, oidSeq.toByteArray());

        // Adding Key
        DerOutputStream keyOctetString = new DerOutputStream();
        keyOctetString.putOctetString(k);
        mainSeq.putOctetString(keyOctetString.toByteArray());

        // Wrapping up in a sequence
        DerOutputStream outStream = new DerOutputStream();
        outStream.write(DerValue.tag_Sequence, mainSeq);
        return outStream.toByteArray();
    }

    /**
     * Extract and return the private key bytes from the output DER returned from GSKit.
     * The XDH privateKeyBytes format is SEQUENCE: [INTEGER (version), SEQUENCE[OID],
     * OCTET STRING[OCTET STRING(private key)]
     * <p>
     * The FFDHE privateKeyBytes format is SEQUENCE: [INTEGER (version), SEQUENCE[OID,
     * SEQUENCE[INTEGER,INTEGER,INTEGER]], OCTET STRING[INTEGER(private key)]
     * <p>
     * The function also sets the params field
     *
     * @param privateKeyBytes
     * @return
     * @throws IOException
     */
    private byte[] extractPrivateKeyFromOCK(byte[] privateKeyBytes) throws IOException {
        DerInputStream in = new DerInputStream(privateKeyBytes);
        DerValue[] inputValue = in.getSequence(3);

        // Retrieve OID and make sure its an XEC/FFDHE curve
        DerInputStream derInputStream = null;
        if (inputValue.length > 1) {
            derInputStream = inputValue[1].getData();
            try {
                processOIDSequence(derInputStream, null);
            } catch (Exception ex) {
                throw new IOException("This curve does not seem to be an XEC or FFDHE curve", ex);
            }
        }

        // Private key is in the form of an octet string stored inside another octet string
        byte[] privData = null;
        if (inputValue.length > 2) {
            privData = inputValue[2].getOctetString();
            if (this.curve.name().contains("FFDH"))
                privData = new DerInputStream(privData).getBigInteger().toByteArray();
            else
                privData = new DerInputStream(privData).getOctetString();
            return privData;
        }
        return null;
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
        try { // FFDH curve
            DerValue[] params = oidInputStream.getSequence(3);
            if (params.length >= 3) {
                bi1 = params[0].getBigInteger();
                bi2 = params[1].getBigInteger();
                bi3 = params[2].getBigInteger();
                int size = bi1.bitLength();
                this.curve = CurveUtil.getCurve(oid, size);
            } else
                throw new IOException("This curve does not seem to be a valid XEC/FFDHE curve");
        } catch (IOException e) { // XEC curve
            this.curve = CurveUtil.getCurve(oid, null);
        }

        if (outStream != null) {
            outStream.putOID(oid);
            if (CurveUtil.isFFDHE(this.curve)) {
                DerOutputStream seq = new DerOutputStream();
                seq.putInteger(bi1);
                seq.putInteger(bi2);
                seq.putInteger(bi3);
                outStream.write(DerValue.tag_Sequence, seq.toByteArray());
            }
        }

        this.params = new NamedParameterSpec(this.curve.name());
        return oid;
    }

    /**
     * Takes a DER encoded key of the following format: SEQUENCE: [version (INTEGER),
     * OID (OID is inside a sequence of 1 element), private key (OCTET STRING)]
     * Returns a similar DER with the last part of the sequence changed to:
     * OCTETSTRING[OCTETSTRING] (Octet string of an octet string which is the private key)
     * It's weird, no idea why it is this way but that's what GSKIT/OpenSSL accepts
     * <p>
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
            throw new IOException("This curve does not seem to be a valid XEC/FFDHE curve");

        if (inputValue[1].getTag() == DerValue.tag_Sequence) {
            DerInputStream oidInputStream = inputValue[1].toDerInputStream();
            DerOutputStream outputOIDSequence = new DerOutputStream();
            oid = processOIDSequence(oidInputStream, outputOIDSequence);
            this.algid = new AlgorithmId(oid);
            outStream.write(DerValue.tag_Sequence, outputOIDSequence.toByteArray());
        } else
            throw new IOException("Unexpected non sequence while parsing private key bytes");

        // Read, convert, then write private key
        byte[] keyBytes = inputValue[2].getOctetString();
        try {
            // XDH private key in SunEC new Java 17 design requires [octet-string[octet-string[key-bytes]]] format,
            // otherwise, it causes interop issue.
            if (isCorrectlyFormedOctetString(keyBytes)) {
                DerInputStream derStream = new DerInputStream(keyBytes);
                k = derStream.getOctetString(); // We know we are working with the format [octet-string[octet-string[key-bytes]]]
            } else {
                k = keyBytes; // Try J11 format [octet-string[key-bytes]]
            }
        } catch (Exception e) {
            //e.printStackTrace();
            k = keyBytes; // Try J11 format [octet-string[key-bytes]]
        }
        setPKCS8KeyByte(k);
        try (DerOutputStream encodedKey = new DerOutputStream()) {
            if (CurveUtil.isFFDHE(this.curve)) {
                BigInteger octetStringAsBigInt = new BigInteger(k);
                encodedKey.putInteger(octetStringAsBigInt); // Put in another octet string
            } else {
                encodedKey.putOctetString(k); // Put in another octet string
            }
            outStream.putOctetString(encodedKey.toByteArray());
        }

        try (DerOutputStream asn1Key = new DerOutputStream()) {
            asn1Key.write(DerValue.tag_Sequence, outStream);
            return asn1Key.toByteArray();
        }
    }


    /**
     * Determines if a given array is a properly formed DER octet string.
     * 
     * @param keyBytes The byte array to check for a complete octet.
     * @return Returns true if the first byte of the array indicates an octet ( 0x04 ) and the
     * value continues to the end of the array indicating a complete octet filling the 
     * given byte array. Returns false otherwise.
     * @throws IOException Throws an IOException when a failure occurs decoding the DER encoded bytes.
     */
    private boolean isCorrectlyFormedOctetString(byte[] keyBytes) throws IOException {
        if (keyBytes == null) {
            return false;
        }

        // Tag value for an octet is 0x04.
        if (keyBytes[0] != 0x04) {
            return false;
        }

        // Attempt to DER decode the given keyBytes.
        DerInputStream derStream = new DerInputStream(keyBytes);
        byte[] keyValue = derStream.getOctetString();

        // We know we are able to DER decode the bytes, lets now check that the private 
        // key bytes are the correct length for the curve in use.
        if (CurveUtil.getCurveSize(this.curve) != keyValue.length) {
            return false;
        }

        return true;
    }

    public XECKey getOCKKey() {
        return this.xecKey;
    }

    /**
     * @return external wrapped java documented instance of NamedParameterSpec
     */
    public AlgorithmParameterSpec getParams() {
        return params;
    }

    public Optional<byte[]> getScalar() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return scalar;
    }

    public byte[] getKeyBytes() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }
        return k.clone();
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
    public String getAlgorithm() {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            this.exception = exception;
        }

        return "XDH";
    }

    /**
     * Adds a sequence of FFDHE integers (bi1, bi2, and bi3) to the OutputStream param.
     * DER added: SEQUENCE[INTEGER,INTEGER,INTEGER]
     *
     * @param oidBytes the OutputStream on which to write the DER encoding.
     * @throws IOException on encoding errors.
     */
    public static void putFFDHEIntegers(DerOutputStream oidBytes, BigInteger bi1, BigInteger bi2,
            BigInteger bi3) throws IOException {
        DerOutputStream oidSubSeq = new DerOutputStream();
        oidSubSeq.putInteger(bi1);
        oidSubSeq.putInteger(bi2);
        oidSubSeq.putInteger(bi3);
        oidBytes.write(DerValue.tag_Sequence, oidSubSeq.toByteArray());
    }

    /**
     * Encodes this object to an OutputStream.
     *
     * @param os the OutputStream on which to write the DER encoding.
     * @throws IOException on encoding errors.
     */
    public void encode(OutputStream os) throws IOException {
        try {
            setFieldsFromXeckey();
        } catch (Exception exception) {
            IOException ike = new IOException("Failed in setFieldsFromXeckey");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

        DerOutputStream bytes = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        // encode the version
        bytes.putInteger(0);

        // encode encryption algorithm
        DerOutputStream oidBytes = new DerOutputStream();
        DerOutputStream oidTmp = new DerOutputStream();
        oidBytes.putOID(algid.getOID());
        switch (this.curve) {
            case X25519:
            case X448:
            case Ed25519:
            case Ed448:
                break;
            case FFDHE2048:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE3072:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE4096:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE6144:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;
            case FFDHE8192:
                putFFDHEIntegers(oidBytes, bi1, bi2, bi3);
                break;

        }
        oidTmp.write(DerValue.tag_Sequence, oidBytes);
        bytes.write(oidTmp.toByteArray());

        // encode encrypted key
        if (k != null) {
            // XDH private key in SunEC and new Java 17 design requires [octet-string[octer-string[key-bytes]]] format,
            // otherwise, it causes interop issue. JCK issue 569
            bytes.putOctetString(new DerValue(DerValue.tag_OctetString, k).toByteArray());
        }

        // wrap everything into a SEQUENCE
        tmp.write(DerValue.tag_Sequence, bytes);

        os.write(tmp.toByteArray());
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (exception != null) {
            String msg = exception.getMessage();
            msg += "\nStack:\n";
            for (StackTraceElement s : exception.getStackTrace())
                msg += "- " + s.toString() + "\n";
            throw new DestroyFailedException(
                    "An exception occurred during the execution of this object: " + msg);
        }
        if (!destroyed) {
            destroyed = true;
            if (k != null)
                Arrays.fill(k, (byte) 0x00);
            if (this.key != null)
                Arrays.fill(this.key, (byte) 0x00);
            this.xecKey = null;
            this.scalar = null;
            this.params = null;
        }
    }

    /**
     * Determines if this key has been destroyed.
     */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed)
            throw new IllegalStateException("This key is no longer valid");
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    }

    /**
     * Set the PKCS8Key key object.
     * 
     * @param k The raw key bytes, without OctetString or DER encoded.
     * @throws IOException 
     */
    private void setPKCS8KeyByte(byte[] k) throws IOException {
        if (Integer.parseInt(provider.getJavaVersionStr()) <= 11) {
            this.key = k;
        } else {
            this.key = new DerValue(DerValue.tag_OctetString, k).toByteArray();
        }
    }
}
