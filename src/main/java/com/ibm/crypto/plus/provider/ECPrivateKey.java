/*
 * Copyright IBM Corp. 2023, 2024
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
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

final class ECPrivateKey extends PKCS8Key implements java.security.interfaces.ECPrivateKey {

    /**
     * 
     */

    private static final long serialVersionUID = -7596809556341742543L;

    private OpenJCEPlusProvider provider = null;
    private BigInteger s;
    private transient ECParameterSpec params;

    private ECPublicKey publicKey = null;
    private byte[] privateKeyBytesEncoded = null;
    private byte[] publicKeyBytes = null;
    ObjectIdentifier namedCurveOID = null;

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

        // The ECParameterSpec object contains:
        // - the cofactor (int)
        // - the EllipticCurve (EllipticCurve)
        // - the generator (ECPoint)
        // - the order (BigInteger)

        // The variables "algid", "version", and "key" all reside within the
        // parent
        // class "PKCS8Key".

        this.provider = provider;
        this.s = s;
        this.params = params;
        // System.out.println("this.s=" + ECUtils.bytesToHex(s.toByteArray()));

        // Get an AlgorithmParameters object that has been initialized with the
        // ECParameters (params).
        AlgorithmParameters myAlgorithmParameters = com.ibm.crypto.plus.provider.ECParameters
                .getAlgorithmParameters(provider, params);

        // Build an AlgorithmId object from the EC_oid and the
        // AlgorithmParameters
        // object just created.
        // algid is defined in the parent class "PKCS8Key".
        algid = new AlgorithmId(AlgorithmId.EC_oid, myAlgorithmParameters);

        // generate the encoding

        // try {
        // key = ECParameters.trimZeroes(s.toByteArray());
        // encode();
        // } catch (IOException e) {
        // throw new InvalidKeyException("could not DER encode x: " +
        // e.getMessage());
        // }


        byte[] sArr = s.toByteArray();
        // convert to fixed-length array
        int numOctets = (params.getOrder().bitLength() + 7) / 8;
        byte[] sOctets = new byte[numOctets];
        int inPos = Math.max(sArr.length - sOctets.length, 0);
        int outPos = Math.max(sOctets.length - sArr.length, 0);
        int length = Math.min(sArr.length, sOctets.length);
        System.arraycopy(sArr, inPos, sOctets, outPos, length);
        DerOutputStream out = new DerOutputStream();
        // PKCS8Key contains the decoding logic for all instances of
        // PrivateKeys.
        // It is checking that this version is set to zero.
        // This section matches with what we do in FIPS70.
        out.putInteger(1); // version 1
        out.putOctetString(sOctets);
        DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());
        key = val.toByteArray();

        try {
            this.publicKeyBytes = null;
            byte[] privateKeyBytes = buildOCKPrivateKeyBytes();
            // System.out.println("ECPrivateKey(s, paramSpec) privateKeyBytes="
            // +
            // ECUtils.bytesToHex(privateKeyBytes));
            byte[] paramBytes = ECParameters.encodeECParameters(this.params);
            this.ecKey = ECKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes,
                    paramBytes);
            // System.out.println("ECPrivateKey(s, paramSpec) This.eckey private
            // bytes="
            // + ECUtils.bytesToHex(ecKey.getPrivateKeyBytes()));
            // System.out.println("ECPrivateKey(s, paramSpec) This.eckey public
            // bytes="
            // + ECUtils.bytesToHex(ecKey.getPublicKeyBytes()));
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

    }

    /**
     * Create a EC private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *            the encoded parameters.
     */
    ECPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        try {
            parseKeyBits();
        } catch (IOException e) {
            throw new InvalidKeyException("parseKeyBits: " + e.getMessage());
        }

        try {
            getEncodedPrivateKeyBytes(encoded);
        } catch (IOException e) {
            // e.printStackTrace();
            throw new InvalidKeyException("getEncodedPrivateKeyBytes " + e.getMessage());
        }
        // System.out.println("After decoding this.publicKey=" +
        // this.publicKey);
        try {
            byte[] privateKeyBytes = privateKeyBytesEncoded; // buildOCKPrivateKeyBytes();
            // System.out.println("ECPrivateKey(byte[]encoded) privateKeyBytes="
            // +
            // ECUtils.bytesToHex(privateKeyBytes));
            byte[] paramBytes = ECParameters.encodeECParameters(params);
            this.ecKey = ECKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes,
                    paramBytes);
            // System.out.println("ECPrivateKey(bytes[] encoded) This.eckey
            // private bytes="
            // + ECUtils.bytesToHex(ecKey.getPrivateKeyBytes()));
            // System.out.println("ECPrivateKey(bytes [] encoded) This.eckey
            // public bytes="
            // + ECUtils.bytesToHex(ecKey.getPublicKeyBytes()));
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    ECPrivateKey(OpenJCEPlusProvider provider, ECKey ecKey) throws InvalidKeyException {

        // System.out.println("ECPrivateKey=" + ecKey.toString());
        this.provider = provider;

        DerOutputStream algidOut = null;
        try {

            algidOut = new DerOutputStream();
            algidOut.putOID(AlgorithmId.EC_oid);
            algidOut.putDerValue(new DerValue(ecKey.getParameters()));
            this.algid = AlgorithmId
                    .parse(new DerValue(DerValue.tag_Sequence, algidOut.toByteArray()));

            this.key = convertOCKPrivateKeyBytes(ecKey.getPrivateKeyBytes());
            this.ecKey = ecKey;
            parseKeyBits();
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EC private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
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

    private void getEncodedPrivateKeyBytes(byte[] encoded) throws IOException {
        // String methodName = "getEncodedPrivateKeyBytes ";
        // System.out.println(methodName + ECUtils.bytesToHex(encoded));
        DerInputStream in = new DerInputStream(encoded);
        DerValue[] inputValue = in.getSequence(3);
        BigInteger tempVersion = inputValue[0].getBigInteger();
        if (tempVersion.compareTo(BigInteger.ZERO) != 0) {
            throw new IOException("Decoding public key failed. The version must be zero");
        }
        ObjectIdentifier curveOID = null;
        if (inputValue.length > 1) {
            // System.out.println("trying to figure out curveOID");
            if (inputValue[1].getTag() == DerValue.tag_Sequence) {
                // System.out.println("It is a sequence");
                DerInputStream oidInputStream = inputValue[1].toDerInputStream();
                // DerValue[] oidValues = oidInputStream.get
                oidInputStream.getOID();
                curveOID = oidInputStream.getOID();
            } else {
                throw new IOException("Unexpected non sequence while parsing private key bytes");
            }
        }

        byte[] privateKeyBytesEncoded = null;
        if (inputValue.length < 2) {
            this.publicKey = null;
            this.privateKeyBytesEncoded = null;
            this.publicKeyBytes = null;
            return;
        }
        privateKeyBytesEncoded = inputValue[2].getDataBytes();
        if (privateKeyBytesEncoded == null) {
            // System.out.println(methodName + "publicKeyBytesEncoded is null");
            this.publicKey = null;
            this.privateKeyBytesEncoded = null;
            this.publicKeyBytes = null;
            return;
        } else {
            this.privateKeyBytesEncoded = privateKeyBytesEncoded;
        }

        // System.out.println(methodName + "privateKeyBytesEncoded=" +
        // ECUtils.bytesToHex(privateKeyBytesEncoded));

        // The JCEFIPS when encoding private key, adds the publicKeyBytes to the
        // privateKey in a different way than other
        // providers
        // The sequence is as follows:
        // Universal SEQ: universal primitve integer version,
        // octect string (private Key bytes),
        // context construted 0 with
        // Universal primary object Id for well known curve
        // Context constructed 1 with
        // Primitive bit string (for JCEPlus, JCE, BC)
        // SEQUENCE:
        // SEQUENCE:
        // Universal primary Object ID for pKCS encoding
        // Universal Primary object ID for parameter curve
        // Primitive bit string
        // Convert the JCEFIPS encoding similar to others
        DerInputStream privKeyBytesEncodedStream = new DerInputStream(privateKeyBytesEncoded);
        DerValue[] inputDerValue = privKeyBytesEncodedStream.getSequence(4);
        if (inputDerValue.length == 2 || inputDerValue.length == 3) {
            BigInteger tempVersion1 = inputDerValue[0].getBigInteger();
            if (tempVersion1.compareTo(BigInteger.ONE) != 0) {
                throw new IOException("Decoding public key failed. The version must be 1");
            }
            byte[] privateKeyBytes = null;
            if (inputDerValue.length > 1)
                privateKeyBytes = inputDerValue[1].getOctetString();

            DerOutputStream outEncodedStream = new DerOutputStream();
            outEncodedStream.putInteger(tempVersion1);
            outEncodedStream.putOctetString(privateKeyBytes);
            // outEncodedStream.putDerValue(paramDerValue);
            DerOutputStream outParamStream = new DerOutputStream();
            outParamStream.putOID(curveOID);
            outEncodedStream.write(
                    DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PARAMETERS_ATTRS),
                    outParamStream.toByteArray());

            DerInputStream paramDerInputStream = null;
            DerValue paramDerValue = null;
            if (inputDerValue.length > 2) {
                paramDerInputStream = inputDerValue[2].getData();
                paramDerValue = paramDerInputStream.getDerValue();
                outParamStream = new DerOutputStream();
                outParamStream.putDerValue(paramDerValue);
                outEncodedStream.write(
                        DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PUBLIC_KEY_ATTRS),
                        outParamStream.toByteArray());
            }

            DerOutputStream asn1Key = new DerOutputStream();
            asn1Key.write(DerValue.tag_Sequence, outEncodedStream.toByteArray());
            // System.out.println("calling asn1Key.toByteArray()");
            this.privateKeyBytesEncoded = asn1Key.toByteArray();

        } else {
            BigInteger tempVersion1 = inputDerValue[0].getBigInteger();
            if (tempVersion1.compareTo(BigInteger.ONE) != 0) {
                throw new IOException("Decoding public key failed. The version must be 1");
            }
            byte[] privateKeyBytes = null;
            if (inputDerValue.length > 1)
                privateKeyBytes = inputDerValue[1].getOctetString();
            DerInputStream paramDerInputStream = null;
            DerValue paramDerValue = null;
            if (inputDerValue.length > 2) {
                paramDerInputStream = inputDerValue[2].getData();
                paramDerValue = paramDerInputStream.getDerValue();
            }
            if (inputDerValue.length > 3
                    && inputDerValue[3].isContextSpecific(TAG_PUBLIC_KEY_ATTRS)) {
                // System.out.println("Encountered a tag_context");
                try {
                    DerInputStream pubKeyStream = inputDerValue[3].getData();
                    byte[] pubKeyBytes = pubKeyStream.getBitString();
                    // System.out.println(methodName + "pubKeyBytes=" +
                    // ECUtils.bytesToHex(pubKeyBytes));

                    // parse the pubKeyBytes to distinguish byte stream from
                    // FIPS vs
                    // other providers
                    DerInputStream inputStream = new DerInputStream(pubKeyBytes);

                    if (inputStream.peekByte() == DerValue.tag_Sequence) {
                        DerValue[] inputDerValuePubBytes = inputStream.getSequence(2);
                        byte[] actualKeyBits = null;
                        if (inputDerValuePubBytes.length > 1) {
                            actualKeyBits = inputDerValuePubBytes[1].getBitString();
                        }
                        // byte[] pubKeyBytesTrimmed =
                        // ECParameters.trimZeroes(pubKeyBytes);

                        // System.out.println(methodName + "pub
                        // KeyBytesTrimmed=" +
                        // ECUtils.bytesToHex(pubKeyBytesTrimmed));
                        // System.out.println(methodName + "actualKeyBits=" +
                        // ECUtils.bytesToHex(actualKeyBits));

                        DerOutputStream outEncodedStream = new DerOutputStream();
                        outEncodedStream.putInteger(tempVersion1);
                        outEncodedStream.putOctetString(privateKeyBytes);
                        // outEncodedStream.putDerValue(paramDerValue);
                        DerOutputStream outParamStream = new DerOutputStream();
                        outParamStream.putDerValue(paramDerValue);
                        outEncodedStream.write(DerValue.createTag(DerValue.TAG_CONTEXT, true,
                                TAG_PARAMETERS_ATTRS), outParamStream.toByteArray());

                        if (actualKeyBits != null) {
                            DerOutputStream tmp1out = new DerOutputStream();
                            tmp1out.putBitString(actualKeyBits);

                            outEncodedStream.write(DerValue.createTag(DerValue.TAG_CONTEXT, true,
                                    TAG_PUBLIC_KEY_ATTRS), tmp1out);
                        }
                        DerOutputStream asn1Key = new DerOutputStream();
                        asn1Key.write(DerValue.tag_Sequence, outEncodedStream.toByteArray());
                        // System.out.println("calling asn1Key.toByteArray()");
                        this.privateKeyBytesEncoded = asn1Key.toByteArray();

                    }
                } catch (Exception ex) {
                    // Unable to parse the key bytes. See if OCK can handle it.
                    // ex.printStackTrace();
                }
            }
        }
        this.publicKeyBytes = this.privateKeyBytesEncoded.clone();

        // System.out
        // .println(methodName + "this.privateKeyBytesEncoded=" +
        // ECUtils.bytesToHex(this.privateKeyBytesEncoded));

    }

    /**
     * Return the privateKeyBytes returned from OCK. The privateKeyBytes format
     * is SEQUENCE: VERSION: INTEGER PrivateKey: OCTET STRING CONTEXT
     * CONSTRUCTED 0 OID (named curve) CONTEXT CONSTRUCTED 1 PublicKey:
     * OCTETSTRING
     * 
     * @param privateKeyBytes
     * @return
     * @throws IOException
     */
    private byte[] convertOCKPrivateKeyBytes(byte[] privateKeyBytes) throws IOException {

        // System.out.println("in ConvertOCKPrivateKeyBytes=" +
        // ECUtils.bytesToHex(privateKeyBytes));

        DerInputStream in = new DerInputStream(privateKeyBytes);
        DerValue[] inputValue = in.getSequence(4);
        BigInteger tempVersion = inputValue[0].getBigInteger();

        byte[] privData = null;
        if (inputValue.length > 1) {
            privData = inputValue[1].getOctetString();
            s = new BigInteger(1, privData);
        } else
            s = null;

        DerInputStream derInputStream = null;
        if (inputValue.length > 2) {
            derInputStream = inputValue[2].getData();
            // System.out.println ("DerTag=" + derInputStream.tag);
            // System.out.println ("Context constructed 0");
            try {
                ObjectIdentifier oid = derInputStream.getOID();
                // System.out.println ("oid = " + oid.toString());
                if (oid != null) {
                    return privateKeyBytes;
                } else {
                    throw new IOException(
                            " The next encoded structure must be a context constructed OID");
                }
            } catch (Exception ex) {
                // Must be a custom curve.
            }
        }
        byte[] publicKeyBit = null;
        DerInputStream derInputStreamPublicKey = null;
        if (inputValue.length > 3) {
            derInputStreamPublicKey = inputValue[3].getData();

            publicKeyBit = derInputStreamPublicKey.getBitString();

        }

        DerOutputStream bytes = new DerOutputStream();
        DerOutputStream asn1Key = new DerOutputStream();
        bytes.putInteger(tempVersion);
        bytes.putOctetString(privData);
        DerOutputStream tmp1out = null;
        if (publicKeyBit != null) {
            tmp1out = new DerOutputStream();
            tmp1out.putBitString(publicKeyBit);
            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PUBLIC_KEY_ATTRS),
                    tmp1out);
        }

        // System.out.println ("successfully wrote public key");
        asn1Key.write(DerValue.tag_Sequence, bytes);
        byte[] customCurve = asn1Key.toByteArray();
        // System.out.println ("Custom curve bytes = " +
        // ECUtils.bytesToHex(customCurve));
        return customCurve;

    }

    private byte[] buildOCKPrivateKeyBytes() throws IOException, InvalidParameterSpecException {

        // System.out.println("In buildOCKPrivateKeyBytes");

        ECParameterSpec params = getParams();

        DerOutputStream bytes = new DerOutputStream();
        DerOutputStream asn1Key = new DerOutputStream();

        // Encode the version
        bytes.putInteger(BigInteger.ONE);

        // Encode Private key
        if (key != null) {

            // The key value is sequence of version, octet string
            DerInputStream in = new DerInputStream(key);
            DerValue derValue = in.getDerValue();

            // System.out.println("derValue.getTag=" + derValue.getTag());
            if (derValue.getTag() != DerValue.tag_Sequence) {
                throw new IOException(MSG_SEQ);
            }
            DerInputStream data = derValue.getData();
            int version = data.getInteger();
            // System.out.println("version=" + version);
            // PKCS8Key contains the decoding logic for all instances of
            // PrivateKeys.
            // It is checking that this version is set to one.
            if (version != 1) {
                throw new IOException(MSG_VERSION1);
            }

            byte[] privData = ECParameters.trimZeroes(data.getOctetString());

            bytes.putOctetString(privData);
        }

        byte[] ecParamEncodedBeforeTrimming = ECParameters.encodeECParameters(params);
        byte[] myEncodedECParameters = ECParameters.trimZeroes(ecParamEncodedBeforeTrimming);
        // System.out.println("ecParamEncodedbeforeTrimming= " +
        // ECUtils.bytesToHex(ecParamEncodedBeforeTrimming));
        DerValue derValue = new DerValue(myEncodedECParameters);
        DerOutputStream tmpout = new DerOutputStream();
        tmpout.putDerValue(derValue);
        bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PARAMETERS_ATTRS), tmpout);

        // encode the OPTIONAL public key
        if (this.publicKeyBytes != null) {
            // System.out.println("publicKeyBytes is not null = " +
            // ECUtils.bytesToHex(this.publicKeyBytes));
            DerOutputStream tmp1out = new DerOutputStream();

            tmp1out.putBitString(publicKeyBytes);

            bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_PUBLIC_KEY_ATTRS),
                    tmp1out);
            // System.out.println("successfully wrote public key");
        }

        // wrap everything into a SEQUENCE
        asn1Key.write(DerValue.tag_Sequence, bytes);
        // System.out.println("wrote tag sequence=" +
        // ECKey.bytesToHex(asn1Key.toByteArray()));

        return asn1Key.toByteArray();
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

    @Override
    public PublicKey calculatePublicKey() {
        try {
            return new ECPublicKey(provider, ecKey);
        } catch (InvalidKeyException exc) {
            throw new ProviderException(
                    "Unexpected error calculating public key", exc);
        }
    }

    /**
     * Parse the key. Called by PKCS8Key. "key" is a byte array containing the
     * Der-encoded key which resides within the parent class PKCS8Key. The
     * PKCS class named PKCS8Key contains the "decode" method for all
     * PrivateKeys. It expects that the PrivateKey it is decoding contains a
     * version number, an AlgorithmID (containing the OID and
     * AlgorithmParameters), and the encoded key itself. It calls parseKeyBits(
     * ) of the appropriate key class to parse the encoded key.
     */
    protected void parseKeyBits() throws IOException {
        // The variables "algid", "version", and "key" all reside within the
        // parent
        // class "PKCS8Key".

        // System.out.println("in parse key bits this.key=" +
        // ECKey.bytesToHex(this.key));

        try {
            // Begin parsing "version" and "s" out of "key"
            DerInputStream in = new DerInputStream(key);
            DerValue derValue = in.getDerValue();

            // System.out.println("derValue.getTag=" + derValue.getTag());
            if (derValue.getTag() != DerValue.tag_Sequence) {
                throw new IOException(MSG_SEQ);
            }
            DerInputStream data = derValue.getData();
            int version = data.getInteger();
            // System.out.println("version=" + version);
            // PKCS8Key contains the decoding logic for all instances of
            // PrivateKeys.
            // It is checking that this version is set to one.
            if (version != 1) {
                throw new IOException(MSG_VERSION1);
            }

            byte[] privData = data.getOctetString();
            s = new BigInteger(1, privData);

            // End parsing "version" and "s" out of "key"
            // System.out.println("s=" + s);

            while (data.available() != 0) {
                DerValue value = data.getDerValue();
                if (!((value.isContextSpecific((byte) 0)) || (value.isContextSpecific((byte) 1)))) {
                    throw new IOException("Unexpected value: " + value);
                }
            }

            AlgorithmParameters algParams = this.algid.getParameters();
            if (algParams == null) {
                throw new IOException(
                        "EC domain parameters must be encoded in the algorithm identifier");
            }
            // System.out.println("algParams=" + algParams);

            params = algParams.getParameterSpec(ECParameterSpec.class);

        } catch (IOException e) {
            // e.printStackTrace();
            throw new IOException("Invalid EC private key");
        } catch (InvalidParameterSpecException e) {
            throw new IOException("Invalid EC private key");
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
