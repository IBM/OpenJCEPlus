/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import com.ibm.crypto.plus.provider.ock.DHKey;

import sun.security.util.BitArray;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.X509Key;

@SuppressWarnings("restriction")
final class DHPublicKey extends X509Key
        implements javax.crypto.interfaces.DHPublicKey, Destroyable {

    /**
     * 
     */

    private static final long serialVersionUID = -2993913181811776154L;

    private OpenJCEPlusProvider provider = null;
    private BigInteger y = null;
    private DHParameters dhParams = null;
    private byte[] key = null;
    private byte[] encodedKey = null;
    private String DH_data = "1.2.840.113549.1.3.1";


    private transient boolean destroyed = false;
    private transient DHKey dhKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

    DHPublicKey(OpenJCEPlusProvider provider, BigInteger y, BigInteger p, BigInteger g)
            throws InvalidKeyException {
        this(provider, y, p, g, 0);
    }

    DHPublicKey(OpenJCEPlusProvider provider, BigInteger y, BigInteger p, BigInteger g,
            int l) throws InvalidKeyException {
        this.provider = provider;
        this.y = y;
        dhParams = new DHParameters(provider);
        try {
            dhParams.engineInit(new DHParameterSpec(p, g, l));
            byte[] keyArray = new DerValue(DerValue.tag_Integer, this.y.toByteArray()).toByteArray();
            setKey(new BitArray(keyArray.length * 8, keyArray));
            this.encodedKey = getEncoded();
        } catch (IOException e) {
            throw new InvalidKeyException("Cannot produce ASN.1 encoding");
        } catch (InvalidParameterSpecException e) {
            throw new InvalidKeyException("Cannot initialize parameters");
        }
    }

    /**
     * Make a DH public key out of a public value <code>y</code>, a prime modulus
     * <code>p</code>, a base generator <code>g</code>, and a private-value length
     * <code>l</code>.
     *
     * @param y
     *            the public value
     * @param p
     *            the prime modulus
     * @param g
     *            the base generator
     * @param l
     *            the private-value length
     *
     * @exception InvalidKeyException
     *                if the key cannot be encoded
     */
    public DHPublicKey(OpenJCEPlusProvider provider, BigInteger y, DHParameters params)
            throws InvalidKeyException {
        this.provider = provider;
        this.y = y;
        this.dhParams = params;
        try {
            byte[] keyArray = new DerValue(DerValue.tag_Integer, this.y.toByteArray()).toByteArray();
            setKey(new BitArray(keyArray.length * 8, keyArray));
            this.encodedKey = getEncoded();
        } catch (IOException e) {
            throw new InvalidKeyException("Cannot produce ASN.1 encoding");
        }
    }

    public DHPublicKey(OpenJCEPlusProvider provider, DHKey dhKey) {
        try {
            this.provider = provider;
            convertOCKPublicKeyBytes(dhKey.getPublicKeyBytes());
            this.dhKey = dhKey;
            parseKeyBits();
        } catch (Exception exception) {
            throw provider.providerException("Failure in DHPublicKey", exception);
        }
    }

    public DHPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        // decode(encoded);

        try {

            // System.out.println ("In DHPublicKey(Provider, byte[] encoded" +
            // ECUtils.bytesToHex(encoded));
            convertOCKPublicKeyBytes(encoded);

            buildOCKPublicKeyBytes();
            // System.out.println ("In DHPublicKey(Provider, byte[] encoded publicKeyBytes"
            // + ECUtils.bytesToHex(publicKeyBytes));

            this.dhKey = DHKey.createPublicKey(provider.getOCKContext(),
                    /* publicKeyBytes */ this.encodedKey);

            // System.err.println("Afte OCK: " + ECUtils.bytesToHex(this.key));

        } catch (IOException ioex) {
            throw new InvalidKeyException("Invalid key format");
        } catch (Exception e) {
            throw provider.providerException("Failure in DHPublicKey", e);
        }
    }

    private byte[] convertOCKPublicKeyBytes(byte[] encodedKey) throws IOException {
        /*
         * DerInputStream in = new DerInputStream(publicKeyBytes); DerValue[] inputValue
         * = in.getSequence(3); BigInteger tempY = inputValue[0].getInteger();
         * BigInteger tempP = inputValue[1].getInteger(); BigInteger tempG =
         * inputValue[2].getInteger();
         * 
         * DerValue outputValue = new DerValue(DerValue.tag_Integer,
         * tempY.toByteArray()); return outputValue.toByteArray();
         */

        InputStream inStream = new ByteArrayInputStream(encodedKey);
        try {
            DerValue derKeyVal = new DerValue(inStream);
            if (derKeyVal.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Invalid key format");
            }

            /*
             * Parse the algorithm identifier
             */
            DerValue algid = derKeyVal.getData().getDerValue();
            if (algid.getTag() != DerValue.tag_Sequence) {
                throw new IOException("AlgId is not a SEQUENCE");
            }
            DerInputStream derInStream = algid.toDerInputStream();
            derInStream.getOID();
            if (derInStream.available() == 0) {
                throw new IOException("Parameters missing");
            }

            /*
             * Parse the parameters
             */
            DerValue params = derInStream.getDerValue();
            if (params.getTag() == DerValue.tag_Null) {
                throw new IOException("Null parameters");
            }
            if (params.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Parameters not a SEQUENCE");
            }
            params.getData().reset();
            BigInteger p = params.getData().getDerValue().getBigInteger();
            BigInteger g = params.getData().getDerValue().getBigInteger();
            int l = -1;
            // Private-value length is OPTIONAL
            if (params.getData().available() != 0) {
                l = params.getData().getInteger();
            }
            if (params.getData().available() != 0) {
                throw new IOException("Extra parameter data");
            }


            /*
             * Parse the key
             */

            byte[] keyArray = derKeyVal.getData().getBitString();
            setKey(new BitArray(keyArray.length * 8, keyArray));

            //customParseKeyBits();
            parseKeyBits();
            if (derKeyVal.getData().available() != 0) {
                throw new InvalidKeyException("Excess key data");
            }

            dhParams = new DHParameters(provider);
            dhParams.engineInit((l == -1) ? new DHParameterSpec(p, g, y.bitLength())
                    : new DHParameterSpec(p, g, l));

            this.encodedKey = encodedKey.clone();

            DerValue outputValue = new DerValue(DerValue.tag_Integer, getKey().toByteArray());

            return outputValue.toByteArray();

        } catch (IOException | NumberFormatException e) {
            throw new IOException("Error parsing key encoding", e);
        } catch (InvalidKeyException e) {
            throw new IOException("Error parsing key material", e);
        } catch (InvalidParameterSpecException e) {
            throw new IOException("Error creating DHParameters", e);
        }
    }

    private byte[] buildOCKPublicKeyBytes() throws Exception {
        // DHParams params = getParams();

        DerValue[] value = new DerValue[3];

        value[0] = new DerValue(DerValue.tag_Integer, this.y.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, dhParams.getP().toByteArray());
        value[2] = new DerValue(DerValue.tag_Integer, dhParams.getG().toByteArray());

        DerOutputStream asn1Key = new DerOutputStream();
        try {
            asn1Key.putSequence(value);
        } catch (IOException e) {
            throw e;
        } finally {
            closeStream(asn1Key);
        }

        return asn1Key.toByteArray();
    }

    protected void parseKeyBits() throws InvalidKeyException {

        try {

            DerInputStream in = new DerInputStream(getKey().toByteArray());
            this.y = in.getBigInteger();

        } catch (IOException e) {
            throw new InvalidKeyException(e.toString());
        }

    }



    /**
     * Returns the key parameters.
     *
     * @return the key parameters
     */
    @Override
    public DHParameterSpec getParams() {
        checkDestroyed();
        try {
            return this.dhParams.engineGetParameterSpec(DHParameterSpec.class);
        } catch (InvalidParameterSpecException e) {
            throw provider.providerException("Failure in DHPublicKey", e);
        }
    }

    /**
     * Returns the name of the algorithm associated with this key: "DH"
     */
    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return "DH";
    }

    /**
     * Returns the encoding format of this key: "X.509"
     */
    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();

        /**
         * Get the encoding of the key.
         */
        DerOutputStream params = null;
        DerOutputStream algid = null;
        DerOutputStream tmpDerKey = null;
        DerOutputStream derKey = null;
        if (this.encodedKey == null) {
            try {
                algid = new DerOutputStream();

                // store oid in algid
                algid.putOID(ObjectIdentifier.of(DH_data));

                // encode parameters
                params = new DerOutputStream();
                params.putInteger(this.dhParams.getP());
                params.putInteger(this.dhParams.getG());
                if (this.dhParams.getL() != 0) {
                    params.putInteger(BigInteger.valueOf(this.dhParams.getL()));
                }
                // wrap parameters into SEQUENCE
                DerValue paramSequence = new DerValue(DerValue.tag_Sequence, params.toByteArray());
                // store parameter SEQUENCE in algid
                algid.putDerValue(paramSequence);

                // wrap algid into SEQUENCE, and store it in key encoding
                tmpDerKey = new DerOutputStream();
                tmpDerKey.write(DerValue.tag_Sequence, algid);

                // store key data
                tmpDerKey.putBitString(getKey().toByteArray());

                // wrap algid and key into SEQUENCE
                derKey = new DerOutputStream();
                derKey.write(DerValue.tag_Sequence, tmpDerKey);
                this.encodedKey = derKey.toByteArray();
            } catch (IOException e) {
                return null;
            } finally {
                closeStream(params);
                closeStream(algid);
                closeStream(tmpDerKey);
                closeStream(derKey);

            }
        }
        return this.encodedKey.clone();
    }

    /**
     * Returns the public value, <code>y</code>.
     *
     * @return the public value, <code>y</code>
     */
    @Override
    public BigInteger getY() {
        checkDestroyed();
        return this.y;
    }

    DHKey getOCKKey() {
        return this.dhKey;
    }

    /**
     * Destroys this key. A call to any of its other methods after this will cause
     * an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *             if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            setKey(new BitArray(0));
            this.dhKey = null;
            this.y = null;
            this.dhParams = null;
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
     * Replace the DHPublicKey key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException
     *             if a new object representing this DESede key could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new KeyRep(KeyRep.Type.PUBLIC, getAlgorithm(), getFormat(), getEncoded());
    }

    public String toString() {
        // public String toString() {
        StringBuffer strbuf = new StringBuffer("OpenJCEPlus Diffie-Hellman Public Key:\n" + "y:\n"
                + (this.y).toString() + "\n" + "p:\n" + (this.dhParams.getP()).toString() + "\n"
                + "g:\n" + (this.dhParams.getG()).toString());
        if (this.dhParams.getL() != 0)
            strbuf.append("\nl:\n" + "    " + this.dhParams.getL());
        return strbuf.toString();
    }

    private void closeStream(DerOutputStream objStream) {

        try {
            objStream.close();
        } catch (IOException e) {
            // Ignore this exception since this method is called from 
            //final class
        }

    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    public int hashCode() {
        Object[] objects = {y, this.dhParams.getP(), this.dhParams.getG()};
        return java.util.Arrays.hashCode(objects);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;

        if (!(obj instanceof javax.crypto.interfaces.DHPublicKey)) {
            return false;
        }

        javax.crypto.interfaces.DHPublicKey other = (javax.crypto.interfaces.DHPublicKey) obj;
        DHParameterSpec otherParams = other.getParams();
        if ((this.y.compareTo(other.getY()) == 0)
                && (this.dhParams.getP().compareTo(otherParams.getP()) == 0)
                && (this.dhParams.getG().compareTo(otherParams.getG()) == 0)) {
            // If the object we're comparing against was not built by this provider
            // we need to also check that hashCode values match.
            // This additional check is/was needed as the equals(..) and hashCode()
            // methods of this class were updated prior to being able to update
            // the methods of the DHPublicKey.
            // Performing this additional check will ensure that we satisfy the 
            // contract for the Object.hashCode() method which states that if two
            // objects are equal according to the equals(Object) method, then 
            // calling the hashCode method on each of the two objects must produce
            // the same integer result.
            //
            if (obj instanceof DHPublicKey) {
                return true;
            } else {
                boolean b = (this.hashCode() == obj.hashCode());
                return b;
            }
        }
        return false;
    }

}
