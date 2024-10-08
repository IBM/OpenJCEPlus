/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.certificateutils;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Arrays;
import sun.security.pkcs.PKCS9Attribute;
import sun.security.pkcs.PKCS9Attributes;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X500Name;
import sun.security.x509.X509Key;

/**
 * Implements the ASN.1 CertificationRequestInfo type as defined in PKCS #10.
 * This information is part of a CertificationRequest.
 *
 * <xmp>
 * CertificationRequestInfo ::= SEQUENCE {
 *    version Version,
 *    subject Name,
 *    subjectPublicKeyInfo SubjectPublicKeyInfo,
 *    attributes [0] IMPLICIT Attributes
 * }
 *
 * SubjectKeyInfo ::= SEQUENCE {
 *    algorithm AlgorithmIdentifier,
 *    publicKey BIT STRING
 * }
 * </xmp>
 *
 * <p>
 * CertificationRequestInfo objects are immutable; they cannot be changed once
 * created.
 *
 * @see AlgorithmId
 * @see CertificationRequest
 */

public final class CertificationRequestInfo extends PKCSDerObject implements Cloneable {

    private static final byte TAG_ATTRIBUTES = 0;

    // The version number (defined as 0 for this version of the standard).
    private static final BigInteger version = BigInteger.ZERO;

    // The distinguished name of the certificate subject (the entity whose
    // public key is to be certified).
    private X500Name subject;

    // Information about the public key being certified.  This includes the
    // algorithm id and the DER-encoded key.

    // The SubjectPublicKeyInfo data type is implemented by the
    // com.ibm.security.util.X509Key class.  However, instead of using X509Key
    // for our private attribute, we will use PublicKey so that we can handle
    // DSAPublicKey objects that inherit from Sun's X509Key and not our X509Key.
    //private X509Key spki;

    private PublicKey spki;

    // Additional information about the subject of the certificate.
    private PKCS9Attributes attributeSet;

    private static Debug debug = Debug.getInstance("jceplus");
    private static String className = "ibm.jceplus.junit.base.certificateutils.CertificationRequestInfo";

    // cached hashCode value
    private volatile int cachedHashVal = 0;

    //
    // Constructors
    //

    /**
     * Create a CertificationRequestInfo object with a DER byte array.
     *
     * @param der a DER byte array encoding a CertificationRequestInfo object.
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequestInfo(byte[] der) throws IOException {
        super(der);
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo", der);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo");
        }
    }

    /**
     * Create a CertificationRequestInfo object with a DER byte array.
     *
     * @param der a DER byte array encoding a CertificationRequestInfo object.
     * @param provname the name of the java security provider the caller wishes
     *                 to use
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequestInfo(byte[] der, String provname) throws IOException {
        super(der, provname);
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo", der, provname);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo");
        }
    }

    /**
     * Create a CertificationRequestInfo object with the specified values.
     *
     * @param subject the disinguished name of the certificate subject.
     * @param key the public key being certified.
     * @param attrs a set of attributes describing the certificate subject.
     * This set may have zero or more elements.  A null attrs argument implies
     * a set with zero elements.
     * @throws IOException
     *
     * @exception IllegalArgumentException if the subject or key info argument
     * is null.
     */
    public CertificationRequestInfo(X500Name subject, PublicKey key, PKCS9Attributes attrs)
            throws IllegalArgumentException, IOException {

        if (debug != null) {
            Object[] parms = {subject, key, attrs};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo", parms);
        }
        if (subject == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo",
                        "No subject specified");
            }
            throw new IllegalArgumentException("No subject specified");
        }
        if (key == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo",
                        "No public key specified");
            }
            throw new IllegalArgumentException("No public key specified");
        }

        this.subject = subject;
        this.spki = key;

        // 000523 - spki is the original PublicKey and not the PublicKey changed
        // to a X509Key.
        /****
        try {
        this.spki = new X509Key();
        byte[] bytes = key.getEncoded();
        
        // DEBUG BEGIN
        //HexDumpEncoder h = new HexDumpEncoder();
        //System.out.println("CertificationRequestInfo(...) key.getEncoded() =\r\n"
        //   + h.encode(bytes));
        // DEBUG END
        
        this.spki.decode(bytes);
        } catch (InvalidKeyException e) {
        throw new IllegalArgumentException(
            "Invalid public key.  The key must be in X.509 format.");
        }
        ****/

        if (attrs != null) {
            this.attributeSet = attrs;
        } else {
            this.attributeSet = new PKCS9Attributes((PKCS9Attribute[]) null);
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo");
        }
    }

    /**
     * Create a CertificationRequestInfo object with the specified values.
     *
     * @param subject the disinguished name of the certificate subject.
     * @param key the public key being certified.
     * @param attrs a set of attributes describing the certificate subject.
     * This set may have zero or more elements.  A null attrs argument implies
     * a set with zero elements.
     * @param provname the name of the java security provider the caller wishes
     *                 to use
     * @throws IOException
     *
     * @exception IllegalArgumentException if the subject or key info argument
     * is null.
     */
    public CertificationRequestInfo(X500Name subject, PublicKey key, PKCS9Attributes attrs,
            String provname) throws IllegalArgumentException, IOException {
        super(provname);
        if (debug != null) {
            Object[] parms = {subject, key, attrs, provname};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo", parms);
        }
        if (subject == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo",
                        "No subject specified");
            }
            throw new IllegalArgumentException("No subject specified");
        }
        if (key == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo",
                        "No public key specified");
            }
            throw new IllegalArgumentException("No public key specified");
        }

        this.subject = subject;
        this.spki = key;

        // 000523 - spki is the original PublicKey and not the PublicKey changed
        // to a X509Key.
        /****
        try {
        this.spki = new X509Key();
        byte[] bytes = key.getEncoded();
        
        // DEBUG BEGIN
        //HexDumpEncoder h = new HexDumpEncoder();
        //System.out.println("CertificationRequestInfo(...) key.getEncoded() =\r\n"
        //   + h.encode(bytes));
        // DEBUG END
        
        this.spki.decode(bytes);
        } catch (InvalidKeyException e) {
        throw new IllegalArgumentException(
            "Invalid public key.  The key must be in X.509 format.");
        }
        ****/

        if (attrs != null) {
            this.attributeSet = attrs;
        } else {
            this.attributeSet = new PKCS9Attributes((PKCS9Attribute[]) null);
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo");
        }
    }

    /**
     * Create a CertificationRequestInfo with the filename of the DER-encoded
     * or BASE64-encoded object.
     *
     * @param filename name of the DER-encoded or base64-encoded object
     * @param base64 true if BASE64-encoded, false if DER-encoded
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequestInfo(String filename, boolean base64) throws IOException {
        super(filename, base64);
        if (debug != null) {
            Object[] parms = {filename, base64};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo", parms);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo");
        }
    }

    /**
     * Create a CertificationRequestInfo with the filename of the DER-encoded
     * or BASE64-encoded object.
     *
     * @param filename name of the DER-encoded or base64-encoded object
     * @param base64 true if BASE64-encoded, false if DER-encoded
     * @param provname the name of the java security provider the caller wishes
     *                 to use
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequestInfo(String filename, boolean base64, String provname)
            throws IOException {
        super(filename, base64, provname);
        if (debug != null) {
            Object[] parms = {filename, base64, provname};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo", parms);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequestInfo");
        }
    }

    //
    // Public methods
    //

    /**
     * Encodes this object to an OutputStream.
     *
     * @param os the OutputStream to write the encoded data to.
     *
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream os) throws IOException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "encode", os);
        }
        DerOutputStream bytes = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        // encode version
        bytes.putInteger(version);

        // encode name
        this.subject.encode(bytes);

        // encode public key info

        bytes.write(this.spki.getEncoded());

        // 000523 - spki is the original PublicKey and not the PublicKey changed
        // to a X509Key.
        /*****
        try {
        bytes.write(this.spki.encode());
        // DEBUG BEGIN
        //spki.write("spki.der");
        // DEBUG END
        } catch (InvalidKeyException e) {
        throw new IOException("Error encoding public key.");
        }
        *****/

        // encode attributes (as IMPLICIT and constructed like other sample
        // cert requests)

        // This was the old way where we didn't encode the attributes as a set,
        // thus the verification of the signature would fail because the derived
        // bytes to be signed (from CertificationRequest.verify calling this method)
        // would not match the original bytes to be signed.
        // To solve this, use the PKCS9Attributes.encode method which will encode
        // the set of attributes properly.

        //PKCS9Attribute[] attrs = this.attributeSet.getAttributes();
        //DerOutputStream derout = new DerOutputStream();
        //for (int i = 0; i < attrs.length; i++) {
        //    attrs[i].encode(derout);
        //}
        //bytes.write(DerValue.createTag(DerValue.TAG_CONTEXT, true, (byte) 0), derout);

        DerOutputStream derout = new DerOutputStream();
        this.attributeSet.encode(DerValue.tag_Set, derout);
        bytes.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT, true, TAG_ATTRIBUTES), derout);

        tmp.write(DerValue.tag_Sequence, bytes);
        os.write(tmp.toByteArray());
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "encode");
        }
    }

    /**
     * Determines if this CertificationRequestInfo object is equivalent to the
     * input object.
     *
     * @param other the object to compare this one to.
     *
     * @return true, if the two objects are equivalent, false otherwise.
     */
    public boolean equals(Object other) {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "equals", other);
        }
        if (other == this) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.TRUE);
            }
            return true;
        }
        if (other instanceof CertificationRequestInfo) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "equals",
                        this.equals((CertificationRequestInfo) other));
            }
            return this.equals((CertificationRequestInfo) other);
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.FALSE);
        }
        return false;
    }

    public int hashCode() {
        if (cachedHashVal == 0) {
            try {
                DerOutputStream thisOut = new DerOutputStream();
                this.encode(thisOut);
                cachedHashVal = Arrays.hashCode(thisOut.toByteArray());
            } catch (Exception e) {
                // this should never occur because if this code fails,
                //then the code in equals() must've failed
                return 0;
            }
        }
        return cachedHashVal;
    }

    /**
     * Returns a string representation of this CertificationRequestInfo object.
     *
     * @return a string representation of this object.
     */
    public String toString() {

        String out = "";

        out += "PKCS #10 Certification request info:";

        out += "\r\n\tversion: " + CertificationRequestInfo.version;

        out += "\r\n\tsubject: " + this.subject;

        out += "\r\n\tpublic key info: \r\n" + spki.toString();

        out += "\r\n\tattributes: " + attributeSet.toString();

        return out;
    }

    /**
     * Creates a clone of this CertificationRequestInfo object.
     *
     * @return clone of this CertificationRequestInfo object.
     */
    public Object clone() {

        try {
            DerOutputStream derout = new DerOutputStream();
            this.encode(derout);
            return (Object) new CertificationRequestInfo(derout.toByteArray(), super.provider);
        } catch (Exception e) {
            return (Object) null;
        }
    }

    /**
     * Returns a reference to the version number.  The version number is an
     * immutable object.
     *
     * @return the version number for this object.
     */
    public BigInteger getVersion() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getVersion");
            debug.exit(Debug.TYPE_PUBLIC, className, "getVersion", version);
        }
        return version;
    }

    /**
     * Returns a reference to the certificate subject name. The subject name is      * an immutable object.
     *
     * @return the certificate subject name for this object.
     */
    public X500Name getSubjectName() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSubjectName");
            debug.exit(Debug.TYPE_PUBLIC, className, "getSubjectName", subject);
        }
        return subject;
    }

    /**
     * Returns a copy of the public key info.
     *
     * @return the public key info for this object.
     *
     * @exception InvalidKeyException if a copy of the public key info cannot
     * be generated.
     */
    public PublicKey getSubjectPublicKeyInfo() throws InvalidKeyException, IOException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSubjectPublicKeyInfo");
        }
        if (this.spki == null) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSubjectPublicKeyInfo", null);
            }
            return null;
        }

        DerValue der = new DerValue(this.spki.getEncoded());
        PublicKey result = X509Key.parse(der);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getSubjectPublicKeyInfo", result);
        }
        return result;

        // 000519 - Return the PublicKey fully parsed.  Not the old way.
        /****
        X509Key key = new X509Key();
        key.decode(this.spki.getEncoded());
        return (PublicKey) key;
        ****/
    }

    /**
     * Returns a reference to the subject's attributes.  The attributes object
     * is immutable.
     *
     * @return the subject attributes for this object.
     */
    public PKCS9Attributes getAttributes() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getAttributes");
            debug.exit(Debug.TYPE_PUBLIC, className, "getAttributes", this.attributeSet);
        }
        return this.attributeSet;
    }

    //
    // Non-public methods
    //

    /**
     * Initializes a CertificationRequestInfo object from a DerValue.  The DER
     * encoding must be in the format specified by the CertificationRequestInfo
     * ASN.1 notation.
     *
     * @param encoding a DER-encoded CertificationRequestInfo object.
     *
     * @exception IOException on parsing error.
     */
    protected void decode(DerValue encoding) throws IOException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "decode", encoding);
        }
        if (encoding.getTag() != DerValue.tag_Sequence) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "decode",
                        "CertificationRequestInfo parsing error");
            }
            throw new IOException("CertificationRequestInfo parsing error");
        }

        // get the version and verify that it is 0
        BigInteger parsedVersion = encoding.getData().getBigInteger();
        if (!parsedVersion.equals(version)) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "decode",
                        "Version mismatch: (supported: " + version + ", parsed: " + parsedVersion);
            }
            throw new IOException(
                    "Version mismatch: (supported: " + version + ", parsed: " + parsedVersion);
        }

        // get the subject
        this.subject = new X500Name(encoding.getData().getDerValue());

        // get the subject key info

        this.spki = X509Key.parse(encoding.getData().getDerValue());

        // 000523 - spki is the original PublicKey and not the PublicKey changed
        // to a X509Key.

        /*****
        try {
        PublicKey key = X509Key.parse(encoding.getData().getDerValue());
        this.spki = new X509Key();
        this.spki.decode(key.getEncoded());
        } catch (InvalidKeyException e) {
        throw new IOException(
            "Error decoding public key; the key must be in X.509 format.");
        }
        *****/

        // DEBUG BEGIN
        /***
        HexDumpEncoder hd = new HexDumpEncoder();
        System.out.println(
        "*** CertificateRequestInfo.decode, getting attributes; encoding.getData() =");
        System.out.println(hd.encodeBuffer(encoding.getData().toByteArray()));
        ***/
        // DEBUG END

        // get the subject attributes
        if (encoding.getData().available() != 0) {
            this.attributeSet = new PKCS9Attributes(encoding.getData());
        } else {
            this.attributeSet = new PKCS9Attributes((PKCS9Attribute[]) null);
        }

        if (encoding.getData().available() != 0) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "decode",
                        "CertificationRequestInfo parsing error - data overrun, bytes = "
                                + encoding.getData().available());
            }
            throw new IOException("CertificationRequestInfo parsing error - data overrun, bytes = "
                    + encoding.getData().available());
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "decode");
        }
    }

    /**
     * Determines if this CertificationRequestInfo object is equivalent to the
     * input object.
     *
     * @param other the CertificationRequestInfo object to compare this one to.
     *
     * @return true, if the two objects are equivalent, false otherwise.
     */
    private boolean equals(CertificationRequestInfo other) {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "equals", other);
        }
        DerValue thisDer, otherDer;
        try {
            DerOutputStream thisOut = new DerOutputStream();
            DerOutputStream otherOut = new DerOutputStream();
            this.encode(thisOut);
            thisDer = new DerValue(thisOut.toByteArray());
            other.encode(otherOut);
            otherDer = new DerValue(otherOut.toByteArray());
        } catch (Exception e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "equals", e);
                debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.FALSE);
            }
            return false;
        }

        if (!thisDer.equals(otherDer)) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.FALSE);
            }
            return false;
        }

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.TRUE);
        }
        return true;
    }
}
