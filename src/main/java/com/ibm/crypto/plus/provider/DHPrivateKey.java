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
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.DestroyFailedException;
import com.ibm.crypto.plus.provider.ock.DHKey;
import com.ibm.crypto.plus.provider.ock.OCKException;

import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

@SuppressWarnings("restriction")
final class DHPrivateKey extends PKCS8Key implements javax.crypto.interfaces.DHPrivateKey {

    /**
     * 
     */

    private static final long serialVersionUID = -9137894705065174379L;

    // only supported version of PKCS#8 Key info
    private static final BigInteger PKCS8_VERSION = BigInteger.valueOf(0);

    private OpenJCEPlusProvider provider = null;
    private BigInteger x = null;
    private DHParameters dhParams = null;
    private byte[] key = null;
    private byte[] encodedKey = null;
    private String DH_data = "1.2.840.113549.1.3.1";

    private transient boolean destroyed = false;
    private transient DHKey dhKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt


    DHPrivateKey(OpenJCEPlusProvider provider, BigInteger x, BigInteger p, BigInteger g)
            throws InvalidKeyException, IOException {
        initDHPrivateKey(provider, x, null, p, g, 0);
    }

    DHPrivateKey(OpenJCEPlusProvider provider, BigInteger x, BigInteger p, BigInteger g,
            int l) throws InvalidKeyException, IOException {
        initDHPrivateKey(provider, x, null, p, g, l);
    }

    /**
     * Make a DH private key out of a private value <code>x</code>, a prime modulus
     * <code>p</code>, and a base generator <code>g</code>.
     *
     * @param x      the private value
     * @param params the DH parameters
     * @throws InvalidKeyException if the key cannot be encoded
     * @throws IOException
     */
    DHPrivateKey(OpenJCEPlusProvider provider, BigInteger x, DHParameters params)
            throws InvalidKeyException, IOException {
        initDHPrivateKey(provider, x, params, null, null, 0);
    }

    private void initDHPrivateKey(OpenJCEPlusProvider provider, BigInteger x, DHParameters dhp,
            BigInteger p, BigInteger g, int l) throws InvalidKeyException {
        this.provider = provider;
        this.x = x;

        if (dhp == null) {
            this.dhParams = new DHParameters(provider);
            try {
                this.dhParams.engineInit(new DHParameterSpec(p, g, l));
            } catch (InvalidParameterSpecException e) {
                throw new InvalidKeyException("Cannot initialize parameters");
            }
        } else {
            this.dhParams = dhp;
        }

        try {
            this.key = new DerValue(DerValue.tag_Integer, this.x.toByteArray()).toByteArray();
            this.encodedKey = getEncoded();
            this.dhKey = DHKey.createPrivateKey(provider.getOCKContext(), encodedKey);
        } catch (IOException e) {
            throw new InvalidKeyException("Cannot produce ASN.1 encoding");
        } catch (OCKException e) {
            throw new InvalidKeyException("Failure in DHPrivateKey");
        }
    }

    DHPrivateKey(OpenJCEPlusProvider provider, DHKey dhKey) {
        try {

            this.provider = provider;
            this.algid = new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.3.1"),
                    new DerValue(dhKey.getParameters()));
            convertOCKPrivateKeyBytes(dhKey.getPrivateKeyBytes());

            this.dhKey = dhKey;
        } catch (Exception exception) {
            throw provider.providerException("Failure in DHPrivateKey", exception);
        }
    }

    DHPrivateKey(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException, IOException {
        this.provider = provider;

        try {
            convertOCKPrivateKeyBytes(encoded);

            buildOCKPrivateKeyBytes();
            this.dhKey = DHKey.createPrivateKey(provider.getOCKContext(),
                    encoded /*privateKeyBytes*/);
        } catch (Exception e) {
            throw new InvalidKeyException("Failure in DHPrivateKey");
        }
    }

    private byte[] convertOCKPrivateKeyBytes(byte[] encodedKey) throws IOException {
        /*
         * DerInputStream in = new DerInputStream(privateKeyBytes); DerValue[]
         * inputValue = in.getSequence(5); BigInteger tempVersion =
         * inputValue[0].getInteger(); BigInteger tempP = inputValue[1].getInteger();
         * BigInteger tempG = inputValue[2].getInteger(); BigInteger tempY =
         * inputValue[3].getInteger(); BigInteger tempX = inputValue[4].getInteger();
         * 
         * DerValue outputValue = new DerValue(DerValue.tag_Integer,
         * tempX.toByteArray()); return outputValue.toByteArray();
         */

        InputStream inStream = new ByteArrayInputStream(encodedKey);
        try {
            DerValue val = new DerValue(inStream);
            if (val.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Key not a SEQUENCE");
            }

            //
            // version
            //
            BigInteger parsedVersion = val.getData().getBigInteger();
            if (!parsedVersion.equals(PKCS8_VERSION)) {
                throw new IOException("version mismatch: (supported: " + PKCS8_VERSION
                        + ", parsed: " + parsedVersion);
            }

            //
            // privateKeyAlgorithm
            //
            DerValue algid = val.getData().getDerValue();
            if (algid.getTag() != DerValue.tag_Sequence) {
                throw new IOException("AlgId is not a SEQUENCE");
            }
            DerInputStream derInStream = algid.toDerInputStream();
            // parse the OID
            derInStream.getOID();
            if (derInStream.available() == 0) {
                throw new IOException("Parameters missing");
            }
            // parse the parameters
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

            //
            // privateKey
            //
            this.key = val.getData().getOctetString();
            parseKeyBits();

            dhParams = new DHParameters(provider);
            dhParams.engineInit((l == -1) ? new DHParameterSpec(p, g, x.bitLength())
                    : new DHParameterSpec(p, g, l));

            // ignore OPTIONAL attributes

            this.encodedKey = encodedKey.clone();

            DerValue outputValue = new DerValue(DerValue.tag_Integer, key);
            return outputValue.toByteArray();

        } catch (IOException | NumberFormatException e) {
            throw new IOException("Error parsing key encoding", e);
        } catch (InvalidParameterSpecException e) {
            throw new IOException("Error creating DHParameters", e);
        }
    }

    private byte[] buildOCKPrivateKeyBytes() throws IOException {

        // Compute the public key
        //
        BigInteger y = dhParams.getG().modPow(x, dhParams.getP());

        DerValue[] value = new DerValue[5];

        value[0] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, dhParams.getP().toByteArray());
        value[2] = new DerValue(DerValue.tag_Integer, dhParams.getG().toByteArray());
        value[3] = new DerValue(DerValue.tag_Integer, y.toByteArray()); // public key
        value[4] = new DerValue(DerValue.tag_Integer, this.x.toByteArray()); // private key

        DerOutputStream asn1Key = new DerOutputStream();
        try {
            asn1Key.putSequence(value);
            return asn1Key.toByteArray();
        } finally {
            closeStream(asn1Key);
        }


    }

    protected void parseKeyBits() throws IOException {
        DerInputStream in = new DerInputStream(key);

        try {
            x = in.getBigInteger();
        } catch (IOException e) {
            throw new IOException("Invalid DH private key", e);
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
     * Returns the encoding format of this key: "PKCS#8"
     */
    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        DerOutputStream derKey = null;
        DerOutputStream params = null;
        checkDestroyed();
        /**
         * Get the encoding of the key.
         */

        if (this.encodedKey == null) {
            try {
                DerOutputStream tmp = new DerOutputStream();

                //
                // version
                //
                tmp.putInteger(PKCS8_VERSION);

                //
                // privateKeyAlgorithm
                //
                DerOutputStream algid = new DerOutputStream();

                // store OID
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
                // wrap algid into SEQUENCE
                tmp.write(DerValue.tag_Sequence, algid);

                // privateKey
                tmp.putOctetString(this.key);

                // make it a SEQUENCE
                derKey = new DerOutputStream();
                derKey.write(DerValue.tag_Sequence, tmp);
                this.encodedKey = derKey.toByteArray();
            } catch (IOException e) {
                return null;
            } finally {
                try {
                    derKey.close();
                } catch (IOException e) {
                    //do nothing
                }
                try {
                    params.close();
                } catch (IOException e) {
                    //do nothing
                }
            }
        }
        return this.encodedKey.clone();

        //return super.getEncoded();
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
            throw provider.providerException("Failure in DHPrivateKey", e);
        }
    }

    /**
     * Returns the private value, <code>x</code>.
     *
     * @return the private value, <code>x</code>
     */
    @Override
    public BigInteger getX() {
        checkDestroyed();
        return this.x;
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
            if (this.key != null) {
                Arrays.fill(this.key, (byte) 0x00);
            }
            this.dhKey = null;
            this.x = null;
            dhParams = null;
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

    DHKey getOCKKey() {
        return this.dhKey;
    }

    private void closeStream(DerOutputStream objStream) {
        try {
            objStream.close();
        } catch (IOException e) {
            // Ignore this exception since this method is called from
            // final class
        }
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    public int hashCode() {
        Object[] objects = {x, this.dhParams.getP(), this.dhParams.getG()};
        return java.util.Arrays.hashCode(objects);
    }

    public boolean equals(Object obj) {
        if (this == obj)
            return true;

        if (!(obj instanceof javax.crypto.interfaces.DHPrivateKey))
            return false;

        javax.crypto.interfaces.DHPrivateKey other = (javax.crypto.interfaces.DHPrivateKey) obj;
        DHParameterSpec otherParams = other.getParams();
        if ((this.x.compareTo(other.getX()) == 0)
                && (this.dhParams.getP().compareTo(otherParams.getP()) == 0)
                && (this.dhParams.getG().compareTo(otherParams.getG()) == 0)) {
            // If the object we're comparing against was not built by this provider
            // we need to also check that hashCode values match.
            // This additional check is/was needed as the equals(..) and hashCode()
            // methods of this class were updated prior to being able to update
            // the methods of the DHPrivateKey.
            // Performing this additional check will ensure that we satisfy the 
            // contract for the Object.hashCode() method which states that if two
            // objects are equal according to the equals(Object) method, then 
            // calling the hashCode method on each of the two objects must produce
            // the same integer result.
            //
            if (obj instanceof DHPrivateKey) {
                return true;
            } else {
                return (this.hashCode() == obj.hashCode());
            }
        }

        return false;
    }


}
