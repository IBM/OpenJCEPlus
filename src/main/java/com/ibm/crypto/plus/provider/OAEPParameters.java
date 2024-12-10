/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import sun.security.util.Debug;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

/**
 * This class implements the OAEP parameters used with the RSA algorithm in OAEP
 * padding. Here is its ASN.1 definition: RSAES-OAEP-params ::= SEQUENCE {
 * hashAlgorithm [0] HashAlgorithm DEFAULT sha1, maskGenAlgorithm [1]
 * MaskGenAlgorithm DEFAULT mgf1SHA1, pSourceAlgorithm [2] PSourceAlgorithm
 * DEFAULT pSpecifiedEmpty }
 */

public final class OAEPParameters extends AlgorithmParametersSpi {

    private String mdName;
    private MGF1ParameterSpec mgfSpec;
    private byte[] p;
    private static ObjectIdentifier OID_MGF1;
    private static ObjectIdentifier OID_PSpecified;

    static {
        try {
            OID_MGF1 = ObjectIdentifier.of("1.2.840.113549.1.1.8");
        } catch (IOException ioe) {
            // should not happen
            OID_MGF1 = null;
        }
        try {
            OID_PSpecified = ObjectIdentifier.of("1.2.840.113549.1.1.9");
        } catch (IOException ioe) {
            // should not happen
            OID_PSpecified = null;
        }
    }

    public OAEPParameters() {}

    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof OAEPParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        OAEPParameterSpec spec = (OAEPParameterSpec) paramSpec;
        mdName = spec.getDigestAlgorithm();
        String mgfName = spec.getMGFAlgorithm();
        if (!mgfName.equalsIgnoreCase("MGF1")) {
            throw new InvalidParameterSpecException("Unsupported mgf " + mgfName + "; MGF1 only");
        }
        AlgorithmParameterSpec mgfSpec = spec.getMGFParameters();
        if (!(mgfSpec instanceof MGF1ParameterSpec)) {
            throw new InvalidParameterSpecException(
                    "Inappropriate mgf " + "parameters; non-null MGF1ParameterSpec only");
        }
        this.mgfSpec = (MGF1ParameterSpec) mgfSpec;
        PSource pSrc = spec.getPSource();
        if (pSrc.getAlgorithm().equals("PSpecified")) {
            p = ((PSource.PSpecified) pSrc).getValue();
        } else {
            throw new InvalidParameterSpecException(
                    "Unsupported pSource " + pSrc.getAlgorithm() + "; PSpecified only");
        }
    }

    protected void engineInit(byte[] encoded) throws IOException {
        DerInputStream der = new DerInputStream(encoded);
        mdName = "SHA-1";
        mgfSpec = MGF1ParameterSpec.SHA1;
        p = new byte[0];
        DerValue[] datum = der.getSequence(3);
        for (int i = 0; i < datum.length; i++) {
            DerValue data = datum[i];
            if (data.isContextSpecific((byte) 0x00)) {
                // hash algid
                mdName = AlgorithmId.parse(data.getData().getDerValue()).getName();
            } else if (data.isContextSpecific((byte) 0x01)) {
                // mgf algid
                AlgorithmId val = AlgorithmId.parse(data.getData().getDerValue());
                if (!val.getOID().equals((Object) OID_MGF1)) {
                    throw new IOException("Only MGF1 mgf is supported");
                }
                byte[] encodedParams = val.getEncodedParams();
                if (encodedParams == null) {
                    throw new IOException("Missing MGF1 parameters");
                }
                AlgorithmId params = AlgorithmId.parse(new DerValue(encodedParams));
                String mgfDigestName = params.getName();
                if (mgfDigestName.equals("SHA-1")) {
                    mgfSpec = MGF1ParameterSpec.SHA1;
                } else if (mgfDigestName.equals("SHA-224")) {
                    mgfSpec = MGF1ParameterSpec.SHA224;
                } else if (mgfDigestName.equals("SHA-256")) {
                    mgfSpec = MGF1ParameterSpec.SHA256;
                } else if (mgfDigestName.equals("SHA-384")) {
                    mgfSpec = MGF1ParameterSpec.SHA384;
                } else if (mgfDigestName.equals("SHA-512")) {
                    mgfSpec = MGF1ParameterSpec.SHA512;
                } else {
                    throw new IOException("Unrecognized message digest algorithm");
                }
            } else if (data.isContextSpecific((byte) 0x02)) {
                // pSource algid
                AlgorithmId val = AlgorithmId.parse(data.getData().getDerValue());
                if (!val.getOID().equals((Object) OID_PSpecified)) {
                    throw new IOException("Wrong OID for pSpecified");
                }
                byte[] encodedParams = val.getEncodedParams();
                if (encodedParams == null) {
                    throw new IOException("Missing pSpecified label");
                }

                DerInputStream dis = new DerInputStream(encodedParams);
                p = dis.getOctetString();
                if (dis.available() != 0) {
                    throw new IOException("Extra data for pSpecified");
                }
            } else {
                throw new IOException("Invalid encoded OAEPParameters");
            }
        }
    }

    protected void engineInit(byte[] encoded, String decodingMethod) throws IOException {
        if ((decodingMethod != null) && (!decodingMethod.equalsIgnoreCase("ASN.1"))) {
            throw new IllegalArgumentException("Only support ASN.1 format");
        }
        engineInit(encoded);
    }

    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        if (paramSpec.isAssignableFrom(OAEPParameterSpec.class)) {
            return paramSpec.cast(
                    new OAEPParameterSpec(mdName, "MGF1", mgfSpec, new PSource.PSpecified(p)));
        } else {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        DerOutputStream tmp2, tmp3;

        // MD
        AlgorithmId mdAlgId;
        try {
            mdAlgId = AlgorithmId.get(mdName);
        } catch (NoSuchAlgorithmException nsae) {
            throw new IOException("AlgorithmId " + mdName + " impl not found");
        }
        tmp2 = new DerOutputStream();
        mdAlgId.encode(tmp2);
        tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0), tmp2);

        // MGF
        tmp2 = new DerOutputStream();
        tmp2.putOID(OID_MGF1);
        AlgorithmId mgfDigestId;
        try {
            mgfDigestId = AlgorithmId.get(mgfSpec.getDigestAlgorithm());
        } catch (NoSuchAlgorithmException nase) {
            throw new IOException(
                    "AlgorithmId " + mgfSpec.getDigestAlgorithm() + " impl not found");
        }
        mgfDigestId.encode(tmp2);
        tmp3 = new DerOutputStream();
        tmp3.write(DerValue.tag_Sequence, tmp2);
        tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 1), tmp3);

        // PSource
        tmp2 = new DerOutputStream();
        tmp2.putOID(OID_PSpecified);
        tmp2.putOctetString(p);
        tmp3 = new DerOutputStream();
        tmp3.write(DerValue.tag_Sequence, tmp2);
        tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 2), tmp3);

        // Put all together under a SEQUENCE tag
        DerOutputStream out = new DerOutputStream();
        out.write(DerValue.tag_Sequence, tmp);
        return out.toByteArray();
    }

    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        if ((encodingMethod != null) && (!encodingMethod.equalsIgnoreCase("ASN.1"))) {
            throw new IllegalArgumentException("Only support ASN.1 format");
        }
        return engineGetEncoded();
    }

    protected String engineToString() {
        StringBuffer sb = new StringBuffer();
        sb.append("MD: " + mdName + "\n");
        sb.append("MGF: MGF1" + mgfSpec.getDigestAlgorithm() + "\n");
        sb.append("PSource: PSpecified "
                + (p.length == 0 ? "" : Debug.toHexString(new BigInteger(p))) + "\n");
        return sb.toString();
    }
}
