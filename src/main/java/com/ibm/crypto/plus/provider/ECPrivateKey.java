/*
 * Copyright IBM Corp. 2023, 2025
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
            throw new InvalidKeyException("Failed to create EC private key", exception);
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
            // Set parameters.
            AlgorithmParameters algParams = this.algid.getParameters();
            if (algParams == null) {
                throw new IOException(
                        "EC domain parameters must be encoded in the algorithm identifier");
            }
            this.params = algParams.getParameterSpec(ECParameterSpec.class);

            // Get from the encoding:
            //    * the private key as a BigInteger (this.s)
            parsePrivateKeyEncoding();

            // Create appropriate encoding and create ecKey.
            byte[] privateKeyBytes = createEncodedPrivateKeyWithParams();
            byte[] paramBytes = ECParameters.encodeECParameters(params);
            this.ecKey = ECKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes,
                    paramBytes, provider);
        } catch (Exception exception) {
            throw new InvalidKeyException("Failed to create EC private key", exception);
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

            AlgorithmParameters algParams = this.algid.getParameters();
            if (algParams == null) {
                throw new IOException(
                        "EC domain parameters must be encoded in the algorithm identifier");
            }
            this.params = algParams.getParameterSpec(ECParameterSpec.class);

            // Get private key encoding from ECKey.
            this.key = ecKey.getPrivateKeyBytes();

            // Get from the encoding:
            //    * the private key as a BigInteger (this.s)
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

        if (inputDerValue.length < 2) {
            throw new IOException("Incorrect EC private key encoding");
        }
        BigInteger tempVersion1 = inputDerValue[0].getBigInteger();
        if (tempVersion1.compareTo(BigInteger.ONE) != 0) {
            throw new IOException("Decoding EC private key failed. The version must be 1");
        }
        outEncodedStream.putInteger(tempVersion1);

        byte[] privateKeyBytes = inputDerValue[1].getOctetString();
        outEncodedStream.putOctetString(privateKeyBytes);

        byte[] encodedParams = this.getAlgorithmId().getEncodedParams();
        if (inputDerValue.length > 2) {
            if (!inputDerValue[2].isContextSpecific(TAG_PARAMETERS_ATTRS)) {
                throw new IOException("Decoding EC private key failed. Third element is not tagged as parameters");
            }
            DerInputStream paramDerInputStream = inputDerValue[2].getData();
            byte[] privateKeyParams = paramDerInputStream.toByteArray();
            
            // Check against the existing parameters created by PKCS8Key.
            if (!Arrays.equals(privateKeyParams, encodedParams)) {
                throw new IOException("Decoding EC private key failed. The params are not the same as PKCS8Key's");
            }
        }
        // The native library needs the ASN.1 DER decoding of the private key to contain the parameters (i.e., the OID).
        outEncodedStream.write(
                    DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PARAMETERS_ATTRS),
                    encodedParams);

        DerOutputStream asn1Key = new DerOutputStream();
        asn1Key.write(DerValue.tag_Sequence, outEncodedStream.toByteArray());
        return asn1Key.toByteArray();
    }

    /**
     * Parse the private key encoding to:
     * - get the key and set it as a BigInteger (i.e., this.s)
     * - get the public key, if available, and check its tag
     *
     * @throws IOException
     */
    private void parsePrivateKeyEncoding() throws IOException {
        DerInputStream privKeyBytesEncodedStream = new DerInputStream(this.key);
        DerValue[] inputDerValue = privKeyBytesEncodedStream.getSequence(4);

        byte[] privateKeyBytes = inputDerValue[1].getOctetString();
        this.s = new BigInteger(1, privateKeyBytes);

        if (inputDerValue.length == 4) {
            if (!inputDerValue[3].isContextSpecific(TAG_PUBLIC_KEY_ATTRS)) {
                throw new IOException("Decoding EC private key failed. Last element is not tagged as public key");
            }
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
}
