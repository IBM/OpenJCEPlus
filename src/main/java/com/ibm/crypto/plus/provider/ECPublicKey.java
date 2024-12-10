/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.ECKey;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyRep;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

final class ECPublicKey extends X509Key
        implements Destroyable, java.security.interfaces.ECPublicKey {

    private static final long serialVersionUID = -3386791752203116789L;

    private OpenJCEPlusProvider provider = null;
    private transient ECPoint w;
    private transient ECParameterSpec params;

    /** The public key (OPTIONAL) */
    protected byte[] publicKeyBytes;

    private transient boolean destroyed = false;
    private transient ECKey ecKey = null;

    /**
     * Make a EC public key from its components
     *
     * @param encoded
     *            the encoded bytes of the public key
     * @throws InvalidParameterSpecException
     */
    ECPublicKey(OpenJCEPlusProvider provider, ECPoint w, ECParameterSpec ecParams)
            throws InvalidKeyException, InvalidParameterSpecException {

        this.provider = provider;
        this.w = w;
        this.params = ecParams;

        algid = new AlgorithmId(AlgorithmId.EC_oid,
                ECParameters.getAlgorithmParameters(provider, ecParams));
        byte[] keyArray = ECParameters.encodePoint(w, this.params.getCurve());
        setKey(new BitArray(keyArray.length * 8, keyArray));

        try {
            byte[] parameterBytes = ECParameters.encodeECParameters(ecParams);
            byte[] publicKeyBytes = buildOCKPublicKeyBytes();
            // System.out.println ("publicKeyBytes.length=" +
            // publicKeyBytes.length);
            // this.ecKey = ECKey.createPublicKey(IBMJCEPlus.getOCKContext(), w,
            // ecParams);
            this.ecKey = ECKey.createPublicKey(provider.getOCKContext(), publicKeyBytes,
                    parameterBytes);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EC public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Make a EC public key from its DER encoding (X.509).
     *
     * @param encoded
     *            the encoded bytes of the public key
     */
    ECPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        decode(encoded);

        try {
            byte[] publicKeyBytes = buildOCKPublicKeyBytes();
            byte[] parameterBytes = ECParameters.encodeECParameters(this.params);
            // System.out.println ("Calling ECKey createPublicKey");
            this.ecKey = ECKey.createPublicKey(provider.getOCKContext(), publicKeyBytes,
                    parameterBytes);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EC public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    ECPublicKey(OpenJCEPlusProvider provider, ECKey ecKey) throws InvalidKeyException {
        this.provider = provider;

        DerOutputStream algidOut = null;
        try {

            algidOut = new DerOutputStream();
            algidOut.putOID(AlgorithmId.EC_oid);
            algidOut.putDerValue(new DerValue(ecKey.getParameters()));
            this.algid = AlgorithmId
                    .parse(new DerValue(DerValue.tag_Sequence, algidOut.toByteArray()));

            byte[] keyArray = convertOCKPublicKeyBytes(ecKey.getPublicKeyBytes());
            setKey(new BitArray(keyArray.length * 8, keyArray));
            this.ecKey = ecKey;
            parseKeyBits();

        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create EC public key");
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

    private byte[] convertOCKPublicKeyBytes(byte[] publicKeyBytes) throws IOException {
        /* OCK return public key Bytes in the right format */
        return publicKeyBytes;
    }

    private byte[] buildOCKPublicKeyBytes() throws IOException {
        // System.out.println ("In buildOCKPublicKeyBytes");
        ECParameterSpec ecParams = this.params;
        ECPoint w = this.w;

        ECParameters ecp = new ECParameters();
        try {
            ecp.engineInit(ecParams);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidParameterException(
                    "Invalid Parameter Specification " + e.getMessage());

        }
        byte[] encodedECPoint = ECParameters.encodePoint(w, ecParams.getCurve());
        // System.out.println ("Encoded end ECPoint length " +
        // encodedECPoint.length);

        // System.out.println ("Back from buildOCKPublicKeyBytes");
        return encodedECPoint;

    }

    /**
     * Parse the key. Called by X509Key.
     */
    protected void parseKeyBits() throws InvalidKeyException {
        try {
            AlgorithmParameters algParams = this.algid.getParameters();
            // System.out.println("++++++ ECPublicKeyImpl, parseKeyBits,
            // algParams=" + algParams.toString()
            // + " this.algid="+this.algid);
            params = algParams.getParameterSpec(ECParameterSpec.class);
            w = ECParameters.decodePoint(getKey().toByteArray(), params.getCurve());

        } catch (IOException e) {
            throw new InvalidKeyException("Invalid EC key", e);
        } catch (InvalidParameterSpecException e) {
            throw new InvalidKeyException("Invalid EC key", e);
        }
    }

    ECKey getOCKKey() {
        return this.ecKey;
    }

    /**
     * Replace the ECPublicKey key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException
     *             if a new object representing this key could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new KeyRep(KeyRep.Type.PUBLIC, getAlgorithm(), getFormat(), getEncoded());
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.security.Key#getFormat()
     */
    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.security.Key#getEncoded()
     */
    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        return super.getEncoded();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.security.interfaces.ECPublicKey#getW()
     */
    @Override
    public ECPoint getW() {
        checkDestroyed();
        return w;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.security.interfaces.ECKey#getParams()
     */
    @Override
    public ECParameterSpec getParams() {
        checkDestroyed();
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "EC";
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
            this.ecKey = null;
            this.w = null;
            this.params = null;
        }
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }
}
