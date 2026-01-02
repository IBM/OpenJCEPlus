/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.ECKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

final class ECPrivateKey extends PKCS8Key implements java.security.interfaces.ECPrivateKey {

    /**
     * 
     */

    private static final long serialVersionUID = -7596809556341742543L;

    private OpenJCEPlusProvider provider = null;
    private BigInteger s;
    private transient ECParameterSpec params;

    private static final byte TAG_PARAMETERS_ATTRS = 0x00;
    private static final byte TAG_PUBLIC_KEY_ATTRS = 0x01;

    private transient boolean destroyed = false;
    private transient ECKey ecKey = null;
    private static final String MSG_VERSION1 = "The encoded byte array sequence must have version number 1";
    private static final String MSG_SEQ = "The next structure in encoded byte array must be a sequence";

    /**
     * Construct a key from its components.
     * 
     * @param s
     * @param params
     * @param publicKey
     */
    ECPrivateKey(OpenJCEPlusProvider provider, BigInteger s, ECParameterSpec params)
            throws InvalidKeyException, InvalidParameterSpecException {

        this.provider = provider;
        this.s = s;
        this.params = params;

        AlgorithmParameters myAlgorithmParameters = com.ibm.crypto.plus.provider.ECParameters
                .getAlgorithmParameters(provider, params);
        this.algid = new AlgorithmId(AlgorithmId.EC_oid, myAlgorithmParameters);

        // Convert s to fixed-length array.
        byte[] sArr = s.toByteArray();
        int numOctets = (params.getOrder().bitLength() + 7) / 8;
        byte[] sOctets = new byte[numOctets];
        int inPos = Math.max(sArr.length - sOctets.length, 0);
        int outPos = Math.max(sOctets.length - sArr.length, 0);
        int length = Math.min(sArr.length, sOctets.length);
        System.arraycopy(sArr, inPos, sOctets, outPos, length);

        try {
            // Generate the private key encoding.
            DerOutputStream out = new DerOutputStream();
            out.putInteger(1); // version 1
            out.putOctetString(sOctets);
            DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());
            key = val.toByteArray();

            // Create appropriate encoding and create ecKey.
            byte[] privateKeyBytes = createEncodedPrivateKeyWithParams();
            byte[] paramBytes = ECParameters.encodeECParameters(this.params);
            this.ecKey = ECKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes,
                    paramBytes, provider);
        } catch (Exception exception) {
            throw new InvalidKeyException("Failed to create EC private key, " + exception.getMessage(), exception);
        }

    }

    /**
     * Create a EC private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *            the encoded parameters.
     */
    ECPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        decode(encoded);
        this.provider = provider;

        try {
            // Get from the encoding:
            //    * the private key as a BigInteger (this.s)
            // and set parameters.
            parsePrivateKeyEncoding();

            // Create appropriate encoding and create ecKey.
            byte[] privateKeyBytes = createEncodedPrivateKeyWithParams();
            byte[] paramBytes = ECParameters.encodeECParameters(params);
            this.ecKey = ECKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes,
                    paramBytes, provider);
        } catch (Exception exception) {
            throw new InvalidKeyException("Failed to create EC private key, " + exception.getMessage(), exception);
        }
    }

    ECPrivateKey(OpenJCEPlusProvider provider, ECKey ecKey) throws InvalidKeyException {

        // System.out.println("ECPrivateKey=" + ecKey.toString());
        this.provider = provider;
        this.ecKey = ecKey;

        // Set algid and params.
        DerOutputStream algidOut = null;
        try {
            algidOut = new DerOutputStream();
            algidOut.putOID(AlgorithmId.EC_oid);
            algidOut.putDerValue(new DerValue(ecKey.getParameters()));
            this.algid = AlgorithmId
                    .parse(new DerValue(DerValue.tag_Sequence, algidOut.toByteArray()));
            // Get private key encoding from ECKey.
            this.key = ecKey.getPrivateKeyBytes();

            // Get from the encoding:
            //    * the private key as a BigInteger (this.s)
            // and set parameters.
            parsePrivateKeyEncoding();
        } catch (Exception exception) {
            throw new InvalidKeyException("Failed to create EC private key", exception);
        } finally {
            if (algidOut != null) {
                try {
                    algidOut.close();
                } catch (IOException e) {
                    throw new InvalidKeyException("Error closing Der output stream.", e);
                }
            }
        }
    }

    /**
     * The native library requires the parameters to be part of the encoding.
     * If they existing encoding doesn't have them, add them. If it does
     * contain them, check against the existing parameters.
     *
     * @return  the new encoding required by the native library
     * @throws IOException
     */
    private byte[] createEncodedPrivateKeyWithParams() throws IOException {
        DerInputStream privKeyBytesEncodedStream = new DerInputStream(this.key);
        DerValue[] inputDerValue = privKeyBytesEncodedStream.getSequence(4);
        DerOutputStream outEncodedStream = new DerOutputStream();

        BigInteger tempVersion1 = inputDerValue[0].getBigInteger();
        outEncodedStream.putInteger(tempVersion1);

        byte[] privateKeyBytes = inputDerValue[1].getOctetString();
        outEncodedStream.putOctetString(privateKeyBytes);

        byte[] encodedParams = this.getAlgorithmId().getEncodedParams();
        // The native library needs the ASN.1 DER decoding of the private key to contain the parameters (i.e., the OID).
        outEncodedStream.write(
                    DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PARAMETERS_ATTRS),
                    encodedParams);

        DerOutputStream asn1Key = new DerOutputStream();
        asn1Key.write(DerValue.tag_Sequence, outEncodedStream.toByteArray());
        return asn1Key.toByteArray();
    }

    /**
     * Check that the encoding is correct and at the same time
     * parse the private key encoding to:
     * - get the key and set it as a BigInteger (i.e., this.s)
     * - check the public key tag, if available
     * - validate the parameters, if available
     *
     * @throws InvalidKeyException
     */
    private void parsePrivateKeyEncoding() throws InvalidKeyException {
        // Parse private key material from PKCS8Key.decode()
        try {
            DerInputStream in = new DerInputStream(this.key);
            DerValue derValue = in.getDerValue();
            if (derValue.tag != DerValue.tag_Sequence) {
                throw new IOException("Not a SEQUENCE");
            }
            DerInputStream data = derValue.data;
            int version = data.getInteger();
            if (version != 1) {
                throw new IOException("Version must be 1");
            }
            byte[] privData = data.getOctetString();
            this.s = new BigInteger(1, privData);

            // Validate parameters stored from PKCS8Key.decode()
            AlgorithmParameters algParams = this.algid.getParameters();
            if (algParams == null) {
                throw new InvalidKeyException("EC domain parameters must be "
                    + "encoded in the algorithm identifier");
            }
            this.params = algParams.getParameterSpec(ECParameterSpec.class);

            if (data.available() == 0) {
                return;
            }

            DerValue value = data.getDerValue();
            if (value.isContextSpecific(TAG_PARAMETERS_ATTRS)) {
                byte[] privateKeyParams = value.getDataBytes();
                byte[] encodedParams = this.getAlgorithmId().getEncodedParams();
                // Check against the existing parameters created by PKCS8Key.
                if (!Arrays.equals(privateKeyParams, encodedParams)) {
                    throw new InvalidKeyException("Decoding EC private key failed. The params are not the same as PKCS8Key's");
                }
                if (data.available() == 0) {
                    return;
                }
                value = data.getDerValue();
            }

            if (!value.isContextSpecific(TAG_PUBLIC_KEY_ATTRS)) {
                throw new InvalidKeyException("Unexpected value: " + value);
            }

            if (data.available() != 0) {
                throw new InvalidKeyException("Encoding has more than 4 values.");
            }

        } catch (IOException | InvalidParameterSpecException e) {
            throw new InvalidKeyException("Invalid EC private key", e);
        }
    }

    public BigInteger getS() {
        checkDestroyed();
        return this.s;
    }

    public ECParameterSpec getParams() {
        checkDestroyed();
        return this.params;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        // system.out.println("calling get encoded");

        byte[] ockEncoded = super.getEncoded();
        // System.out.println("ECPrivateKey.getEncoded=" + ockEncoded.length + "
        // " +
        // ECKey.bytesToHex(ockEncoded));
        return ockEncoded;
    }

    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    ECKey getOCKKey() {
        return this.ecKey;
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
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
            if (this.key != null) {
                Arrays.fill(this.key, (byte) 0x00);
            }
            this.ecKey = null;
            this.s = null;
        }
    }

    /** Determines if this key has been destroyed. */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }

    /**
     * Compares two private keys.
     *
     * The PKCS8Key.equals() method that compares encodings is used first.
     *
     * If that fails, we compare the private part of the key and the params to validate equivalence,
     * since the keys might be equal but have different encodings if one or more of the optional
     * parts are missing.
     *
     * @param object the object with which to compare
     * @return {@code true} if this key is equal to the object argument; {@code false} otherwise.
     */
    @Override
    public boolean equals(Object object) {
        boolean sameEncoding = super.equals(object);
        if (!sameEncoding) {
            if (!(object instanceof java.security.interfaces.ECPrivateKey)) {
                return false;
            }

            java.security.interfaces.ECPrivateKey ecObj =
                    (java.security.interfaces.ECPrivateKey) object;
            // 1. Compare the secret scalar (S)
            if (!this.getS().equals(ecObj.getS())) {
                return false;
            }

            // 2. Compare the Curve Parameters
            ECParameterSpec s1 = this.getParams();
            ECParameterSpec s2 = ecObj.getParams();

            return ECUtils.equals(s1, s2);
        }

        return true;
    }
}
