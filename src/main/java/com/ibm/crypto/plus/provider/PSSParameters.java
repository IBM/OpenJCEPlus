/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

/**
 * This class implements encoding and decoding of RSA-PSS parameters
 * as specified in RFC 3447
 *
 * ASN.1 from RFC 3279 follows. Note that X9.62 (2005) has added some additional
 * options.
 *
 * <pre>
 * Its ASN.1 definition in PKCS#1 standard is described below:

 RSASSA-PSS-params ::= SEQUENCE {
 hashAlgorithm      [0] OAEP-PSSDigestAlgorithms  DEFAULT sha1,
 maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
 saltLength         [2] INTEGER  DEFAULT 20,
 trailerField       [3] INTEGER  DEFAULT 1
 }


 where

 OAEP-PSSDigestAlgorithms    ALGORITHM-IDENTIFIER ::= {
 { OID id-sha1 PARAMETERS NULL   }|
 { OID id-sha256 PARAMETERS NULL }|
 { OID id-sha384 PARAMETERS NULL }|
 { OID id-sha512 PARAMETERS NULL },
 ...  -- Allows for future expansion --
 }

 PKCS1MGFAlgorithms    ALGORITHM-IDENTIFIER ::= {
 { OID id-mgf1 PARAMETERS OAEP-PSSDigestAlgorithms },
 ...  -- Allows for future expansion --
 }

 *
 * </pre>
 * The PSSParameterSpec class also has a member for storing mgf parameters.
 *
 */

/**
 *ok
 */
public final class PSSParameters extends AlgorithmParametersSpi {

    private AlgorithmId hashAlgorithm;
    private AlgorithmId maskGenAlgorithm;
    private AlgorithmParameterSpec mgfParameterSpec;
    private int saltLength;
    private int trailerField;
    private PSSParameterSpec spec;

    private static final PSSParameterSpec DEFAULT_SPEC = new PSSParameterSpec("SHA-1",
                                                                              "MGF1",
                                                                              MGF1ParameterSpec.SHA1,
                                                                              20,
                                                                              1);

    byte TAG0 = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x00);
    byte TAG1 = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x01);
    byte TAG2 = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x02);
    byte TAG3 = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x03);

    /**
    *
    */
    public PSSParameters() {
        super();
    }

    /**
     * Initialize the PSSParameters by a PSSParameterSpec
     *
     * @param paramSpec
     *            the RSAPSS algorithm parameter spec for this instance.
     */
    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof PSSParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        PSSParameterSpec spec = (PSSParameterSpec) paramSpec;

        String mgfName = spec.getMGFAlgorithm();
        if (!spec.getMGFAlgorithm().equalsIgnoreCase("MGF1")) {
            throw new InvalidParameterSpecException("Unsupported mgf " + mgfName + "; MGF1 only");
        }
        AlgorithmParameterSpec mgfSpec = spec.getMGFParameters();
        if (!(mgfSpec instanceof MGF1ParameterSpec)) {
            throw new InvalidParameterSpecException(
                    "Inappropriate mgf " + "parameters; non-null MGF1ParameterSpec only");
        }
        //System.out.println ("engineInit (ParamSpec)" + paramSpec.toString());
        try {
            this.hashAlgorithm = AlgorithmId.get(spec.getDigestAlgorithm());
            this.maskGenAlgorithm = AlgorithmId.get(spec.getMGFAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidParameterSpecException(e.toString());
        }

        this.mgfParameterSpec = ((PSSParameterSpec) paramSpec).getMGFParameters();
        this.saltLength = ((PSSParameterSpec) paramSpec).getSaltLength();
        this.trailerField = ((PSSParameterSpec) paramSpec).getTrailerField();
        this.spec = spec;

    }

    /**
     * Initialize the PSSParameters by encoded bytes
     *
     * @param params
     *            the encoded bytes of the parameters.
     */
    protected void engineInit(byte[] params) throws IOException {

        this.spec = decodePSSParameters(params);

    }

    /**
     * Initialize the PSSParameters by encoded bytes with the specified decoding
     * method.
     *
     * @param params
     *            the encoded bytes of the parameters.
     * @param format
     *            the decoding method to be used.
     */
    protected void engineInit(byte[] params, String format) throws IOException {
        if ((format != null) && (!format.equalsIgnoreCase("ASN.1"))) {
            throw new IllegalArgumentException("Only support ASN.1 format");
        }
        engineInit(params);
    }

    /**
     * Returns the parameters in encoded bytes.
     * 
     * Only non default values will be encoded. With a single non default value, the encoding for hash looks as follows;
     * CONTEXT_CONSTRUCTED_0
     *         UNIVERSAL_CONSTRUCTED_SEQUENCE
     *             UNIVERSAL_PRIMITIVE_OBJECT_ID
     *          UNIVERSAL_PRIMITIVE_NULL
     *      
     * CONTEXT_CONSTRUCTED_1
     *         UNIVERSAL_CONSTRUCTED_SEQUENCE
     *             UNIVERSAL_PRIMITIVE_OBJECT_ID
     *          UNIVERSAL_CONSTRUCTRED_SEQUENCE
     *              UNIVERSAL_PRIMITIVE_OBJECT_ID
     *              UNIVERSAL_PRIMITIVE_NULL
     *      
     * CONTEXT_CONSTRUCTED_2
     *         UNIVERSAL_PRIMITIVE_INTEGER
     *             
     * CONTEXT_CONSTRUCTED_3
     *         UNIVERSAL_PRIMITIVE_INTEGER
     *      
     *      
     *      
     *      
     * @return byte[] the encoded parameters
     */
    protected byte[] engineGetEncoded() throws IOException {

        // System.err.println("Inside the method encodedPSSparameters");

        DerOutputStream out = new DerOutputStream();

        String hashAlgName = this.hashAlgorithm.getName();
        String defaultHashAlgName = null;
        try {
            defaultHashAlgName = (AlgorithmId.get(DEFAULT_SPEC.getDigestAlgorithm()))
                    .getName();
        } catch (NoSuchAlgorithmException nsae) {
            defaultHashAlgName = null;
        }
        //        if (!this.hashAlgorithm.getName().equalsIgnoreCase(
        //                DEFAULT_SPEC.getDigestAlgorithm())) {

        //System.out.println ("hashAlgorithName=" + hashAlgName);
        //System.out.println ("defaulthashAlgorithName=" + defaultHashAlgName);

        if (!hashAlgName.equalsIgnoreCase(defaultHashAlgName)) {
            DerValue derValueHash = encodeHashAlg(this.hashAlgorithm);
            out.putDerValue(derValueHash);

        }
        // out.putTag(DerValue.TAG_UNIVERSAL, true, (byte) 0x00);
        if (!this.maskGenAlgorithm.getName()
                .equalsIgnoreCase(DEFAULT_SPEC.getMGFAlgorithm())) {
            //System.out.println("MaskGenAlg are different");
            DerValue derValueMaskGen = encodeMaskGenAlg(this.maskGenAlgorithm,
                    this.mgfParameterSpec);
            out.putDerValue(derValueMaskGen);
        } else if (this.mgfParameterSpec != null) {
            String mgf1DigestAlgName = ((MGF1ParameterSpec) (this.mgfParameterSpec))
                    .getDigestAlgorithm();
            String normDigestAlgName = null;
            AlgorithmParameterSpec defaultAlgParamSpec = DEFAULT_SPEC
                    .getMGFParameters();
            String defaultMGFDigest = null;
            try {
                normDigestAlgName = (AlgorithmId.get(mgf1DigestAlgName)).getName();

                defaultMGFDigest = (AlgorithmId
                        .get(((MGF1ParameterSpec) defaultAlgParamSpec).getDigestAlgorithm()))
                                .getName();
                //                System.out.println ("normDigestAlgName=" + normDigestAlgName);
                //                System.out.println ("defaultMGFdigest=" + defaultMGFDigest);

            } catch (NoSuchAlgorithmException e) {
                out.close();
                throw new IOException("NoSuchAlgorithmException during encoding operations.");
            }
            if (normDigestAlgName != null
                    && !normDigestAlgName.equalsIgnoreCase(defaultMGFDigest)) {
                //System.out.println("calling put MGF parameters");
                DerValue derValueMaskGen = encodeMaskGenAlg(this.maskGenAlgorithm,
                        this.mgfParameterSpec);
                out.putDerValue(derValueMaskGen);
            }

        }

        if (this.saltLength != DEFAULT_SPEC.getSaltLength()) {

            DerValue derValueSalt = encodeSalt(this.saltLength);
            out.putDerValue(derValueSalt);

        }
        if (this.trailerField != DEFAULT_SPEC.getTrailerField()) {
            DerValue derValueTrailerField = encodeTrailerField(this.trailerField);
            out.putDerValue(derValueTrailerField);

        }
        DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());
        byte[] encodedPSSParameters = val.toByteArray();
        out.close();

        return encodedPSSParameters;
    }

    /**
     * Encodes non default salt length
     * @param salt
     * @return
     * @throws IOException
     *  CONTEXT_CONSTRUCTED_2
     *         UNIVERSAL PRIMARY INTEGER
     */
    private DerValue encodeSalt(int salt) throws IOException {

        try {

            DerOutputStream out = new DerOutputStream();

            byte tag = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x02);

            out.putInteger(this.saltLength);

            // Observe that the DerValues above are the
            // "data" of the DerValue with the SEQUENCE TAG
            DerValue val = new DerValue(tag, out.toByteArray());
            out.close();
            return val;

        } catch (IOException e) {
            throw new IOException("Exception in hashAlgorithm(): " + e);
        }
    }

    /**
     * Encodes non default TrailerField
     * @param trailerField
     * @return
     * @throws IOException
     * CONTEXT_CONSTRUCTED_3
     *         UNIVERSAL PRIMARY INTEGER
     */
    private DerValue encodeTrailerField(int trailerField) throws IOException {

        try {

            DerOutputStream out = new DerOutputStream();

            byte tag = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x03);

            out.putInteger(trailerField);

            // Observe that the DerValues above are the
            // "data" of the DerValue with the SEQUENCE TAG
            DerValue val = new DerValue(tag, out.toByteArray());
            out.close();

            return val;

        } catch (IOException e) {
            throw new IOException("Exception in hashAlgorithm(): " + e);
        }
    }

    /**
     * Encodes hash algorithm
     * CONTEXT_CONSTRUCTED_0
     *         UNIVERSAL_CONSTRUCTED_SEQUENCE
     *             UNIVERSAL_PRIMITIVE_OBJECT_ID
     *          UNIVERSAL_PRIMITIVE_NULL
     * @param hashAlgorithm
     * @return
     * @throws IOException
     */

    private DerValue encodeHashAlg(AlgorithmId hashAlgorithm) throws IOException {

        try {

            DerOutputStream out = new DerOutputStream();

            out.putOID((hashAlgorithm).getOID());
            out.putNull();

            // Observe that the DerValues above are the
            // "data" of the DerValue with the SEQUENCE TAG
            DerValue val1 = new DerValue(DerValue.tag_Sequence, out.toByteArray());
            out.close();

            DerOutputStream out1 = new DerOutputStream();
            out1.putDerValue(val1);
            byte tag = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x00);

            DerValue val = new DerValue(tag, out1.toByteArray());
            out1.close();

            return val;

        } catch (IOException e) {
            throw new IOException("Exception in hashAlgorithm(): " + e);
        }
    }

    /**
     * Decodes the HashAlgorithm
     * 
     * @param encodedHashAlg
     * @return
     * @throws IOException
     */

    private AlgorithmId decodeHashAlgorithm(DerValue encodedHashAlg) throws IOException {

        //System.out.println("encodedHashAlg=" + encodedHashAlg);
        try {

            if (encodedHashAlg.getTag() != TAG0) {
                throw new IOException("Not a TAG0 encoding");
            }


            DerInputStream data1 = encodedHashAlg.getData();
            DerValue derValue1 = data1.getDerValue();
            //System.out.println("derValue1=" + derValue1);

            DerInputStream data = derValue1.getData();

            ObjectIdentifier hashOID = data.getOID();

            AlgorithmId hashAlgID = new AlgorithmId(hashOID);

            //System.out.println("hashAlgorithmId= "
            //        + hashAlgID);

            return hashAlgID;

        } catch (IOException e) {
            throw new IOException("Exception in decodeHashAlgorithm (): " + e);
        }
    }

    /**
     * Decodes the salt Length
     * 
     * @param encodedSaltLength
     * @return
     * @throws IOException
     */

    private int decodeSaltLength(DerValue encodedSaltLength) throws IOException {

        //System.out.println("encodeSaltLength=" + encodedSaltLength);
        try {

            if (encodedSaltLength.getTag() != TAG2) {
                throw new IOException("Not a TAG2 encoding");
            }


            DerInputStream data = encodedSaltLength.getData();

            int saltLength = data.getInteger();


            //System.out.println("saltLength= "
            //        + saltLength);

            return saltLength;

        } catch (IOException e) {
            throw new IOException("Exception in decodeSaltLength (): " + e);
        }
    }

    /**
     * Decodes the TrailerField
     * @param encodedTrailerField
     * @return
     * @throws IOException
     */
    private int decodeTrailerField(DerValue encodedTrailerField) throws IOException {

        //System.out.println("encodeTrailerField=" + encodedTrailerField);
        try {

            if (encodedTrailerField.getTag() != TAG3) {
                throw new IOException("Not a TAG3 encoding for trailerField");
            }


            DerInputStream data = encodedTrailerField.getData();

            int trailerField = data.getInteger();


            //System.out.println("trailerField= "
            //        + trailerField);

            return trailerField;

        } catch (IOException e) {
            throw new IOException("Exception in decodeTrailerField (): " + e);
        }
    }

    /**
     *   UNIVERSAL_CONSTRUCTED_SEQUENCE
     *              UNIVERSAL_PRIMITIVE_OBJECT_ID
     *          UNIVERSAL_CONSTRUCTRED_SEQUENCE
     *              UNIVERSAL_PRIMITIVE_OBJECT_ID
     *              UNIVERSAL_PRIMITIVE_NULL
     *      
     * Encode MaskGenrationfunction and the digest algorithm used by mgf1
     * @param maskGenAlgorithm
     * @param mgf1ParameterSpec
     * @return
     * @throws IOException
     */

    private DerValue encodeMaskGenAlg(AlgorithmId maskGenAlgorithm,
            AlgorithmParameterSpec mgf1ParameterSpec) throws IOException {
        try {

            DerOutputStream out = new DerOutputStream();
            out.putOID((maskGenAlgorithm).getOID());

            if (mgfParameterSpec != null) {
                DerValue mgfDigest = encodeMgfParameterSpec(mgfParameterSpec);
                out.putDerValue(mgfDigest);

            }
            out.close();

            // Observe that the DerValues above are the
            // "data" of the DerValue with the SEQUENCE TAG
            DerValue val1 = new DerValue(DerValue.tag_Sequence, out.toByteArray());
            DerOutputStream out1 = new DerOutputStream();
            out1.putDerValue(val1);
            byte tag = DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0x01);

            DerValue val = new DerValue(tag, out1.toByteArray());
            out1.close();

            return val;

        } catch (IOException e) {
            throw new IOException("Exception in MGF1Parameters: " + e);
        }
    }

    /**
     * encode MGF'1 digest
     *         UNIVERSAL_CONSTRUCTRED_SEQUENCE
     *              UNIVERSAL_PRIMITIVE_OBJECT_ID
     *              UNIVERSAL_PRIMITIVE_NULL
     * 
     * @return
     * @throws IOException
     */
    private DerValue encodeMgfParameterSpec(AlgorithmParameterSpec mgfParameterSpec)
            throws IOException {

        try {

            DerOutputStream out = new DerOutputStream();
            String mgfDigestName = ((MGF1ParameterSpec) (mgfParameterSpec)).getDigestAlgorithm();

            out.putOID((AlgorithmId.get(mgfDigestName)).getOID());
            out.putNull();

            // Observe that the DerValues above are the
            // "data" of the DerValue with the SEQUENCE TAG
            DerValue val = new DerValue(DerValue.tag_Sequence, out.toByteArray());
            out.close();

            return val;

        } catch (IOException e) {
            throw new IOException("Exception in encodeMGfParameterSpec(): " + e);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            throw new IOException("Exception in encodeMGfParameterSpec(): " + e);
        }
    }

    /**
     * Decode the asn.1 sequence 
     * Check for sequences and parse through each sequence.
     * @param encodedPSSParameters
     * @return
     * @throws IOException
     * * 
     * Only non default values will be encoded. With a single non default value, the encoding for hash looks as follows;
     * CONTEXT_CONSTRUCTED_0
     *         UNIVERSAL_CONSTRUCTED_SEQUENCE
     *             UNIVERSAL_PRIMITIVE_OBJECT_ID
     *          UNIVERSAL_PRIMITIVE_NULL
     *      
     * CONTEXT_CONSTRUCTED_1
     *         UNIVERSAL_CONSTRUCTED_SEQUENCE
     *             UNIVERSAL_PRIMITIVE_OBJECT_ID
     *          UNIVERSAL_CONSTRUCTRED_SEQUENCE
     *              UNIVERSAL_PRIMITIVE_OBJECT_ID
     *              UNIVERSAL_PRIMITIVE_NULL
     *      
     * CONTEXT_CONSTRUCTED_2
     *         UNIVERSAL_PRIMITIVE_INTEGER
     *             
     * CONTEXT_CONSTRUCTED_3
     *         UNIVERSAL_PRIMITIVE_INTEGER
     * @throws NoSuchAlgorithmException 
     */

    private PSSParameterSpec decodePSSParameters(byte[] encodedPSSParameters) throws IOException {

        //System.out.println("encodedPSSParameters=" + encodedPSSParameters);

        try {
            DerInputStream derInputStreamParams = new DerInputStream(encodedPSSParameters);

            DerValue[] values = derInputStreamParams.getSequence(0);
            if (values == null) {
                //empty parameters.
                return null;
            }
            //System.out.println("values.length=" + values.length);

            try {
                this.hashAlgorithm = AlgorithmId.get(DEFAULT_SPEC.getDigestAlgorithm());
            } catch (NoSuchAlgorithmException e1) {
                throw new IOException("NoSuchAlgorithmException during decoding operations.");
            }
            try {
                this.maskGenAlgorithm = AlgorithmId.get(DEFAULT_SPEC.getMGFAlgorithm());
            } catch (NoSuchAlgorithmException e) {
                throw new IOException("NoSuchAlgorithmException during decoding operations.");
            }
            this.mgfParameterSpec = DEFAULT_SPEC.getMGFParameters();
            this.saltLength = DEFAULT_SPEC.getSaltLength();
            this.trailerField = DEFAULT_SPEC.getTrailerField();
            for (int i = 0; i < values.length; i++) {
                byte tag = values[i].getTag();
                if (tag == TAG0) {

                    this.hashAlgorithm = decodeHashAlgorithm(values[i]);
                    //System.out.println("Decoded Hash=" + this.hashAlgorithm);
                } else if (tag == TAG1) {
                    this.maskGenAlgorithm = decodeMaskGenAlgorithm(values[i]);
                    //System.out.println("Decoded maskGen=" + this.maskGenAlgorithm);
                } else if (tag == TAG2) {
                    this.saltLength = decodeSaltLength(values[i]);
                    //System.out.println("Decoded saltLength=" + this.saltLength);
                } else if (tag == TAG3) {
                    this.trailerField = decodeTrailerField(values[i]);
                    //System.out.println("Decoded Trailer field=" + this.trailerField);
                } else {
                    //System.out.println ("Unknown tag in the asn.1 encoding" + tag);
                    throw new IOException("Unknown tag in the asn.1 encoding" + tag);

                }
            }



            PSSParameterSpec pssParameterSpec = new PSSParameterSpec(hashAlgorithm.getName(),
                    maskGenAlgorithm.getName(), mgfParameterSpec, saltLength, trailerField);

            return pssParameterSpec;
        } catch (IOException e) {
            throw new IOException("Exception in decodePSSParameters(): " + e);
        }
    }

    /**
     * Decodes maskGen Algorithm
     * @param encodedMaskGenAlg
     * @return
     * @throws IOException
     */
    private AlgorithmId decodeMaskGenAlgorithm(DerValue encodedMaskGenAlg) throws IOException {
        try {
            DerInputStream data1 = encodedMaskGenAlg.getData();
            DerValue derValue1 = data1.getDerValue();
            //System.out.println("derValue1=" + derValue1);

            // this.mgfParameterSpec = decodeParameterSpec(encodedHashAlg));
            if (derValue1.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Not a SEQUENCE");
            }
            DerInputStream data = derValue1.getData();

            ObjectIdentifier maskGenOID = data.getOID();

            AlgorithmId maskGenAlgID = new AlgorithmId(maskGenOID);

            if (data.available() > 0) {
                DerValue encodedMGF1Parameters = data.getDerValue();
                this.mgfParameterSpec = decodeMGF1ParameterSpec(encodedMGF1Parameters);
                //System.out.println("mgfParameterSpec(digestAlg)="
                //        + ((MGF1ParameterSpec) mgfParameterSpec)
                //                .getDigestAlgorithm());
            } else {
                throw new IOException("Missing MGF1 parameters");
            }

            return maskGenAlgID;

        } catch (IOException e) {
            throw new IOException("Exception in decodeMaskGenAlgorithm (): " + e);
        }
    }

    /**
     * Decodes MGF1Parameters
     * @param encodedMGF1Parameters
     * @return
     * @throws IOException
     */
    private AlgorithmParameterSpec decodeMGF1ParameterSpec(DerValue encodedMGF1Parameters)
            throws IOException {
        try {

            // this.mgfParameterSpec = decodeParameterSpec(encodedHashAlg));
            if (encodedMGF1Parameters.getTag() != DerValue.tag_Sequence) {
                throw new IOException("Not a SEQUENCE");
            }
            DerInputStream data = encodedMGF1Parameters.getData();
            ObjectIdentifier mgf1DigestOID = data.getOID();
            String mgf1DigestName = (new AlgorithmId(mgf1DigestOID)).getName();
            AlgorithmParameterSpec mgf1ParameterSpec = (AlgorithmParameterSpec) new MGF1ParameterSpec(
                    mgf1DigestName);

            return mgf1ParameterSpec;
        } catch (IOException e) {
            throw new IOException("Exception in decodeMGF1ParameterSpec(): " + e);
        }
    }

    /**
     * Returns the parameters in encoded bytes with encoding method specified.
     *
     * @return byte[] encoded parameters.
     */
    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        if ((encodingMethod != null) && (!encodingMethod.equalsIgnoreCase("ASN.1"))) {
            throw new IllegalArgumentException("Only support ASN.1 format");
        }
        return engineGetEncoded();
    }

    /**
     * Return the parameter spec used by this parameter instance.
     *
     * @param paramSpec
     *            the parameter spec class to be returned
     *
     * @return AlgorithmParameterSpec the newly generated parameterSpec
     */
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpecClass)
            throws InvalidParameterSpecException {
        if (paramSpecClass.isAssignableFrom(java.security.spec.PSSParameterSpec.class)) {
            return paramSpecClass.cast(new PSSParameterSpec(this.hashAlgorithm.getName(),
                                                            this.maskGenAlgorithm.getName(),
                                                            this.mgfParameterSpec,
                                                            this.saltLength,
                                                            this.trailerField)) ;
        } else {
            throw new InvalidParameterSpecException("Inappropriate parameter Specification");
        }
    }

    //    protected void engineSetParameter(AlgorithmParameterSpec params)
    //            throws InvalidAlgorithmParameterException {
    //        System.out.println ("engineSetParameter called");
    //         if (!(params instanceof PSSParameterSpec)) {
    //                throw new InvalidAlgorithmParameterException(
    //                        "Unsupported parameter: " + params + ". Only "
    //                                + PSSParameterSpec.class.getName() + " supported");
    //          }
    //          PSSParameterSpec spec = (PSSParameterSpec) params;
    //         // this.hashAlgorithm = spec.getMGFAlgorithm()
    //          this.saltLength = spec.getSaltLength();
    //          this.trailerField = spec.getTrailerField();
    //          this.mgfParameterSpec = spec.getMGFParameters();
    //          
    //    }

    /*
     * Returns a formatted string describing the parameters.
     */
    protected String engineToString() {
        String mdName = (mgfParameterSpec == null) ? hashAlgorithm.getName()
                : ((MGF1ParameterSpec) mgfParameterSpec).getDigestAlgorithm();
        return "\n\thashAlgorithm: " + hashAlgorithm + "\n\tmaskGenAlgorithm: " + maskGenAlgorithm
                + "\n\tmgf1ParameterSpec: " + mdName + "\n\tsaltLength: "
                + Integer.toString(saltLength) + "\n\ttrailerField: "
                + Integer.toString(trailerField) + "\n";
    }

    /**
     * Get Algorithmic parameters
     * @param spec
     * @return
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     */
    protected static AlgorithmParameters getAlgorithmParameters(PSSParameterSpec spec)
            throws InvalidKeyException, InvalidParameterSpecException {
        try {

            AlgorithmParameters params = AlgorithmParameters.getInstance(RSAUtil.RSAPSS_NAME,
                    "OpenJCEPlus");
            params.init(spec);
            return params;
        } catch (GeneralSecurityException e) {
            throw new InvalidParameterSpecException("Unsupported parameter specification: " + e);
        }
    }

    /**
     * Used for debugging.
     * @param data
     * @return
     */
    String toHex(byte[] data) {
        String digits = "0123456789abcdef";
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

}

