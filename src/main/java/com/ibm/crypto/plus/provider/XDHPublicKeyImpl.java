/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.CurveUtil.CURVE;
import com.ibm.crypto.plus.provider.ock.XECKey;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyRep;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.X509Key;

final class XDHPublicKeyImpl extends X509Key implements XECPublicKey, Destroyable, Serializable {

    // Field serialVersionUID per tag [SERIALIZATION] in DesignNotes.txt
    private static final long serialVersionUID = 7187392471159151072L;

    private OpenJCEPlusProvider provider = null;
    private transient NamedParameterSpec params;
    private CURVE curve;
    private BigInteger u;
    private BigInteger bi1; // parameter used in FFDHE
    private BigInteger bi2; // parameter used in FFDHE
    private BigInteger bi3; // parameter used in FFDHE

    private transient boolean destroyed = false;
    private transient XECKey xecKey = null;
    private static final byte TAG_PARAMETERS_ATTRS = 0x00;

    private void setFieldsFromXeckey() throws Exception {
        byte[] keyArray = xecKey.getPublicKeyBytes();

        this.params = new NamedParameterSpec(curve.name());

        setKey(new BitArray(keyArray.length * 8, keyArray));

        //if(curve.toString().contains("FFDHE")) keyArray = extractFFDHEPublicKey(keyArray);

        reverseByteArray(keyArray);
        //Clear extra bits
        int bMod8 = (keyArray.length * 8) % 8;
        if (bMod8 != 0) {
            int msk = (1 << bMod8) - 1;
            keyArray[0] &= (byte)msk;
        }

        this.u = new BigInteger(1, keyArray); // u is the public key reversed
    }

    /**
     * Make a XEC public key from its components
     *
     * @param provider
     * @param xeckey
     *            the internal XECKey object that is key will contain
     * @throws InvalidParameterSpecException
     */
    public XDHPublicKeyImpl(OpenJCEPlusProvider provider, XECKey xecKey,
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
    }

    /**
     * Make a XEC public key from its components
     *
     * @param provider
     * @param encoded
     *            the encoded bytes of the public key
     * @throws InvalidParameterSpecException
     */
    public XDHPublicKeyImpl(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException {
        if (provider == null)
            throw new InvalidKeyException("provider cannot be null");
        if (encoded == null)
            throw new InvalidKeyException("encoded key cannot be null");

        this.provider = provider;
        decode(encoded); // Set key, algid, and encodedKey from input

        try {
            byte[] reverseKey = getKey().toByteArray();
            if (!(CurveUtil.isEd(this.curve)))
                reverseByteArray(reverseKey);


            //Clear extra bits
            int bMod8 = (reverseKey.length * 8) % 8;
            if (bMod8 != 0) {
                int msk = (1 << bMod8) - 1;
                reverseKey[0] &= (byte)msk;
            }

            this.u = new BigInteger(1, reverseKey); // u is the public key reversed

            byte[] alteredEncoded = alterEncodedPublicKey(encoded); // Alters encoded to fit GSKit, and sets params
            this.xecKey = XECKey.createPublicKey(provider.getOCKContext(), alteredEncoded);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create XEC public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Make a XEC public key from its parameters
     *
     * @param provider
     * @param u the "u" parameter of the public XEC key to generate
     * @param params must be a NamedParamterSpec
     * @throws InvalidParameterException
     */
    public XDHPublicKeyImpl(OpenJCEPlusProvider provider, AlgorithmParameterSpec params,
            BigInteger u) throws InvalidParameterException, InvalidKeyException {

        if (provider == null) {
            throw new InvalidParameterException("provider must not be null");
        }
        
        if (params instanceof NamedParameterSpec) {
            this.params = (NamedParameterSpec) params;
        } else {
            throw new InvalidParameterException("Invalid Parameters: " + params);
        }

        this.curve = CurveUtil.getCurve(this.params.getName());

        try {
            if (CurveUtil.isFFDHE(this.curve))
                throw new InvalidParameterException("FFDHE algorithms are not suppoerted");
        } catch (Exception e) {
            throw new InvalidParameterException(e.getMessage());
        }

        this.provider = provider;


        try {
            if (u == null) {
                int keySize = CurveUtil.getCurveSize(curve);
                this.xecKey = XECKey.generateKeyPair(provider.getOCKContext(), curve.ordinal(), keySize);
                setFieldsFromXeckey();
            } else {

                byte[] uByteA = null;

                if (!(CurveUtil.isEd(this.curve))) {
                    BigInteger p;
                    BigInteger TWO = BigInteger.valueOf(2);

                    if (this.params.getName().equals("X448")) {
                        p = TWO.pow(448).subtract(TWO.pow(224)).subtract(BigInteger.ONE);
                    } else { //X25519
                        p = TWO.pow(255).subtract(BigInteger.valueOf(19));
                    }

                    this.u = u.mod(p);

                    uByteA = this.u.toByteArray();

                    //The u is reversed for X keys but not Ed keys.
                    reverseByteArray(uByteA);
                }

                //Array might be to big our too small
                uByteA = Arrays.copyOf(uByteA,
                        CurveUtil.getCurveSize(this.curve));

                setKey(new BitArray(uByteA.length * 8, uByteA));

                this.algid = CurveUtil.getAlgId(this.curve);
                byte[] der = buildICCPublicKeyBytes();
                checkKeySize();

                this.xecKey = XECKey.createPublicKey(provider.getOCKContext(), der);
            }
        } catch (InvalidKeyException ex) {
            throw ex;
        } catch (Exception exception) {
            InvalidParameterException ike = new InvalidParameterException(
                    "Failed to create XEC public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Validate that the key is of the correct size
     */
    private void checkKeySize() throws InvalidKeyException {
        if ((CurveUtil.getCurveSize(this.curve) * 8) != getKey().length()) {
            throw new InvalidKeyException(
                    "key length must be " + CurveUtil.getCurveSize(this.curve));
        }
    }

    /**
     * Builds DER from public key to be used to build EVP_PKEY in GSKit
     * DER form: SEQUENCE: [SEQUENCE[OID], BITSTRING]
     * 
     * @param rawPublicKey
     * @return
     * @throws IOException
     */
    private byte[] buildICCPublicKeyBytes() throws IOException {
        DerOutputStream mainSeq = new DerOutputStream();
        DerOutputStream outStream = new DerOutputStream();
        DerOutputStream subSeq = new DerOutputStream();

        // Sequence containing only one element: the OID
        subSeq.putOID(this.algid.getOID());
        if (CurveUtil.isFFDHE(this.curve))
            XDHPrivateKeyImpl.putFFDHEIntegers(outStream, bi1, bi2, bi3);

        // Forming main sequence
        outStream.write(DerValue.tag_Sequence, subSeq.toByteArray());
        outStream.putBitString(getKey().toByteArray());

        mainSeq.write(DerValue.tag_Sequence, outStream);
        return mainSeq.toByteArray();
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
        } else
            throw new IOException("DER sequence does not contain public key");

        DerOutputStream asn1Key = new DerOutputStream();
        asn1Key.write(DerValue.tag_Sequence, outStream);

        return asn1Key.toByteArray();
    }

    private byte[] extractFFDHEPublicKey(byte[] der) throws IOException {
        DerInputStream in = new DerInputStream(der);
        DerValue[] inputValue = in.getSequence(2);
        if (inputValue.length < 2)
            throw new IOException("This curve does not seem to be a valid FFDHE curve");

        // Get OID and verify that its FFDHE curve
        DerInputStream derInputStream = null;
        derInputStream = inputValue[0].getData();

        processOIDSequence(derInputStream, null);
        DerInputStream publicBitString = new DerInputStream(inputValue[1].getBitString());
        return publicBitString.getBigInteger().toByteArray();
    }

    /**
     * Reverses a byte array (in place)
     * 
     * @param array
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

    XECKey getOCKKey() {
        return this.xecKey;
    }

    public BigInteger getU() {
        return u;
    }

    /**
     * @return external wrapped java documented instance of NamedParameterSpec
     */
    public AlgorithmParameterSpec getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
    }

    /**
     * Returns the DER-encoded form of the key as a byte array.
     */
    public byte[] getEncoded() {
        try {
            if (CurveUtil.isXEC(this.curve))
                return getKey().toByteArray();
            if (encodedKey == null) {
                DerOutputStream asn1 = new DerOutputStream();

                DerOutputStream oidSubSeq = null;
                if (CurveUtil.isFFDHE(this.curve)) {
                    oidSubSeq = new DerOutputStream();
                    oidSubSeq.putInteger(bi1);
                    oidSubSeq.putInteger(bi2);
                    oidSubSeq.putInteger(bi3);
                }

                DerOutputStream oidSeq = new DerOutputStream();
                oidSeq.putOID(this.algid.getOID());
                if ((oidSubSeq != null)) {
                    oidSeq.write(DerValue.tag_Sequence, oidSubSeq);
                } else if (Integer.parseInt(provider.getJavaVersionStr()) <= 11) {
                    // Encode as old J8 format
                    // Sun old versions, 11 and before, are not supporting new XDH format,
                    // otherwise, it causes interop issue -> Ex. J11#1834
                    oidSeq.putNull();
                }

                DerOutputStream bitString = null;
                if (CurveUtil.isFFDHE(this.curve)) {
                    bitString = new DerOutputStream();
                    bitString.putInteger(new BigInteger(getKey().toByteArray()));
                }

                DerOutputStream main = new DerOutputStream();
                main.write(DerValue.tag_Sequence, oidSeq);
                if (bitString != null)
                    main.putBitString(bitString.toByteArray());
                else
                    main.putBitString(getKey().toByteArray());

                asn1.write(DerValue.tag_Sequence, main.toByteArray());
                encodedKey = asn1.toByteArray();

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
                throw new InvalidKeyException("Key does not appear to be a XEC/FFDHE key");

            DerInputStream seq = values[0].toDerInputStream();
            processOIDSequence(seq, null);
            this.algid = CurveUtil.getAlgId(this.params.getName());

            byte[] keyArray;
            if (CurveUtil.isFFDHE(this.curve)) {
                DerInputStream bitString = new DerInputStream(values[1].getBitString());
                keyArray = bitString.getBigInteger().toByteArray();
            } else {
                keyArray = values[1].getBitString();
            }
            setKey(new BitArray(keyArray.length * 8, keyArray));
        } catch (Exception e) {
            throw new InvalidKeyException("Key does not appear to be a XEC/FFDHE key");
        }
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *             if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            setKey(new BitArray(0));
            this.xecKey = null;
            this.u = null;
            this.params = null;
        }
    }

    private void checkDestroyed() {
        if (destroyed)
            throw new IllegalStateException("This key is no longer valid");
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        return new KeyRep(KeyRep.Type.PUBLIC, getAlgorithm(), getFormat(), getEncoded());
    }
}
