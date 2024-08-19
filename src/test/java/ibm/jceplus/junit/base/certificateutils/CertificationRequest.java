/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.certificateutils;

import com.ibm.misc.Debug;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Locale;
import sun.security.pkcs.PKCS9Attributes;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.HexDumpEncoder;
import sun.security.util.SignatureUtil;
import sun.security.x509.AlgorithmId;

/**
 * A PKCS #10 certificate request is created and sent to a Certificate
 * Authority, which then creates an X.509 certificate (or perhaps a PKCS #6
 * extended certificate) and returns it to the entity that requested it.
 *
 * <p>
 * A certificate request basically consists of the subject's X.500 name,
 * public key, and zero or more attributes, signed using the subject's
 * private key.
 *
 * <p>
 * The ASN.1 syntax for a Certification Request is:
 *
 * <xmp>
 * CertificationRequest ::= SEQUENCE {
 *    certificationRequestInfo  CertificationRequestInfo,
 *    signatureAlgorithm        SignatureAlgorithmIdentifier,
 *    signature                 Signature
 * }
 *
 * SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
 * Signature ::= BIT STRING
 *
 * CertificationRequestInfo ::= SEQUENCE {
 *    version                 Version,
 *    subject                 Name,
 *    subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *    attributes [0] IMPLICIT Attributes
 * }
 * Attributes ::= SET OF Attribute
 * </xmp>
 *
 * <p>
 * CertificationRequest objects are immutable; they cannot be changed once
 * created.
 *
 * @see CertificationRequestInfo
 * @see AlgorithmId
 */

public final class CertificationRequest extends PKCSDerObject implements Cloneable {

    private static String BEGIN_REQUEST = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    private static String END_REQUEST = "-----END NEW CERTIFICATE REQUEST-----";

    private CertificationRequestInfo certReqInfo;
    private AlgorithmId sigAlg;
    private byte[] signature; // signed cert request info
    private String provider = null;

    private static Debug debug = Debug.getInstance("jceplus");
    private static String className = "ibm.jceplus.junit.base.certificateutils.CertificationRequest";

    //
    // Constructors
    //

    /**
     * Create a CertificationRequest object with a DER byte array.
     *
     * @param der a DER byte array encoding a CertificationRequest object.
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequest(byte[] der) throws IOException {
        super(der);
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", der);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
    }

    /**
     * Create a CertificationRequest object with a DER byte array.
     *
     * @param der a DER byte array encoding a CertificationRequest object.
     * @param provname a string containing the name of the java security provider
     *                 that the caller is using
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequest(byte[] der, String provname) throws IOException {
        super(der, provname);
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", der, provname);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
    }

    /**
     * Constructs a signed PKCS #10 certificate request.
     *
     * @param info the information, including subject name, public key
     *        and attributes, to include in the certification request.
     * @param privateKey Private key used in signing.
     * @param digest the digest used in the signing operation.  Valid
     * values are MD2, MD5 and SHA when using RSA private keys, or SHA when
     * using DSA private keys.
     *
     * @exception NoSuchAlgorithmException if the public key algorithm is not
     * supported in this environment.
     * @exception IOException on encoding errors.
     * @exception PKCSException on signing errors.
     */
    public CertificationRequest(CertificationRequestInfo certReqInfo, PrivateKey privateKey,
            String digest) throws NoSuchAlgorithmException, IOException, PKCSException {

        if (debug != null) {
            Object[] parms = {certReqInfo, privateKey, digest};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", parms);
        }
        this.certReqInfo = certReqInfo;
        try {
            this.signThis(digest, privateKey);
        } catch (SignatureException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "CertificationRequest", e);
            }
            throw new PKCSException(e, "Error signing CertificateRequest: " + e.toString());
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
    }

    /**
     * Constructs a signed PKCS #10 certificate request.
     *
     * @param info the information, including subject name, public key
     *        and attributes, to include in the certification request.
     * @param privateKey Private key used in signing.
     * @param digest the digest used in the signing operation.  Valid
     * values are MD2, MD5 and SHA when using RSA private keys, or SHA when
     * using DSA private keys.
     * @param provname a string containing the name of the java security provider
     *                 that the caller is using
     *
     * @exception NoSuchAlgorithmException if the public key algorithm is not
     * supported in this environment.
     * @exception IOException on encoding errors.
     * @exception PKCSException on signing errors.
     */
    public CertificationRequest(CertificationRequestInfo certReqInfo, PrivateKey privateKey,
            String digest, String provname)
            throws NoSuchAlgorithmException, IOException, PKCSException {

        if (debug != null) {
            Object[] parms = {certReqInfo, privateKey, digest, provname};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", parms);
        }
        if (provname != null) {
            super.provider = new String(provname);
        }
        //        this(certReqInfo, privateKey, digest);

        this.certReqInfo = certReqInfo;
        try {
            this.signThis(digest, privateKey);
        } catch (SignatureException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "CertificationRequest", e);
            }
            throw new PKCSException(e, "Error signing CertificateRequest: " + e.toString());
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
    }

    /**
     * Constructs an unsigned PKCS #10 certificate request.  Before this
     * request may be used, it must be encoded and signed.  Then it
     * must be retrieved in some conventional format (e.g. string).
     *
     * @param info the CertificationRequestInfo object containing subject
     * name, public key and attibute information.
     */
    public CertificationRequest(CertificationRequestInfo info) {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", info);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
        this.certReqInfo = info;
    }

    /**
     * Constructs an unsigned PKCS #10 certificate request.  Before this
     * request may be used, it must be encoded and signed.  Then it
     * must be retrieved in some conventional format (e.g. string).
     *
     * @param info the CertificationRequestInfo object containing subject
     * name, public key and attibute information.
     * @param provname a string containing the name of the java security provider
     *                 that the caller is using
     */
    public CertificationRequest(CertificationRequestInfo info, String provname) {
        super(provname);
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", info, provname);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
        this.certReqInfo = info;
    }

    /**
     * Create a CertificationRequest with the filename of the DER-encoded
     * or BASE64-encoded object.
     *
     * @param filename name of the DER-encoded or base64-encoded object
     * @param base64 true if BASE64-encoded, false if DER-encoded
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequest(String filename, boolean base64) throws IOException {
        super(filename, base64);
        if (debug != null) {
            Object[] parms = {filename, base64};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", parms);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
    }

    /**
     * Create a CertificationRequest with the filename of the DER-encoded
     * or BASE64-encoded object.
     *
     * @param filename name of the DER-encoded or base64-encoded object
     * @param base64 true if BASE64-encoded, false if DER-encoded
     * @param provname a string containing the name of the java security provider
     *                 that the caller is using
     *
     * @exception IOException on decoding errors.
     */
    public CertificationRequest(String filename, boolean base64, String provname)
            throws IOException {
        super(filename, base64, provname);
        if (debug != null) {
            Object[] parms = {filename, base64, provname};
            debug.entry(Debug.TYPE_PUBLIC, className, "CertificationRequest", parms);
            debug.exit(Debug.TYPE_PUBLIC, className, "CertificationRequest");
        }
    }

    //
    // Public methods
    //

    /**
     * Encodes this object to an OutputStream.  The certification request must
     * be signed before it can be encoded.
     *
     * @param os the OutputStream to write the encoded data to.
     *
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream os) throws IOException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "encode", os);
        }
        if ((this.sigAlg == null) || (this.signature == null)) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "encode",
                        "Cannot encode unsigned certification request.");
            }
            throw new IOException("Cannot encode unsigned certification request.");
        }

        DerOutputStream bytes = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        // encode the certification request information
        this.certReqInfo.encode(bytes);

        // encode the signature algorithm id
        this.sigAlg.encode(bytes);

        // encode the signed request
        bytes.putBitString(this.signature);

        tmp.write(DerValue.tag_Sequence, bytes);
        os.write(tmp.toByteArray());
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "encode");
        }
    }

    /**
     * Creates a signature for this certificate request.  This will later be
     * retrieved in either string or binary format.
     *
     * @param digest the digest used in the signing operation.  Valid
     * values are MD2, MD5 and SHA when using RSA private keys, or SHA when
     * using DSA private keys.
     * @param key the private key used to sign the certification request
     * information.
     *
     * @exception PKCSException on signing errors.
     */
    public CertificationRequest sign(String digest, PrivateKey key)
            throws PKCSException, SignatureException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "sign", digest, key);
        }
        if (digest == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "sign", "digest must be specified.");
            }
            throw new IllegalArgumentException("digest must be specified.");
        }
        if (key == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "sign", "key must be specified.");
            }
            throw new IllegalArgumentException("key must be specified.");
        }
        if (this.signature != null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "sign", "Request is already signed.");
            }
            throw new SignatureException("Request is already signed.");
        }

        CertificationRequest certreq = new CertificationRequest(this.certReqInfo, super.provider);

        certreq.signThis(digest, key);

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "sign", certreq);
        }
        return (certreq);
    }

    /**
     * Verifies the request's signature.  This method is typically called
     * immediately after constructing or decoding a CertificationRequest with
     * DER-encoded input.
     *
     * @exception IOException on errors encoding the request information or
     * decoding the stored public key.
     * @exception SignatureException if the signature is invalid.
     * @exception NoSuchAlgorithmException if the signature
     *  algorithm is not supported in this environment.
     */
    public void verify() throws IOException, SignatureException, NoSuchAlgorithmException {

        Signature sig = null;
        AlgorithmParameters sigParams = null;

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "verify");
        }

        try {
            // Get a Signature instance based on the signature algorithm.
            // DEBUG BEGIN
            /***
            System.out.println(
                "*** CertificationRequest.verify() getting Signature for "
                + sigAlg.getName());
            ***/
            // DEBUG END
            if (super.provider != null) {
                try {
                    sig = Signature.getInstance(sigAlg.getName(), super.provider);
                } catch (NoSuchProviderException nspe) {
                    if (debug != null) {
                        debug.exception(Debug.TYPE_PUBLIC, className, "verify", nspe);
                    }
                    throw new IOException("provider " + super.provider + " not found " + nspe);
                }
            } else {
                sig = Signature.getInstance(sigAlg.getName());
            }

            // Get a PublicKey to init the Signture with.  The encoded key
            // must be an X.509Key (which RSA, DSA and DH keys are) and
            // we must instantiate the right kind of public key to init the
            // Signature object with -- X509Key parse does this for us.

            // 000519 - getSubjectPublicKeyInfo now returns the PublicKey fully parsed
            // so we don't need to do the parsing here.
            /****
            DerValue der;
            PublicKey tmpKey = this.certReqInfo.getSubjectPublicKeyInfo();
            der = new DerValue(tmpKey.getEncoded());
            PublicKey key = X509Key.parse(der);
            ****/

            PublicKey key = this.certReqInfo.getSubjectPublicKeyInfo();

            // DEBUG BEGIN
            //System.out.println("*** CertificationRequest.verify() PublicKey = " + key);
            // DEBUG END

            // Generate a signature of the DER-encoding of this object's
            // certification request info and compare it to the existing
            // signature attribute.

            try {
                sigParams = sig.getParameters();
            } catch (UnsupportedOperationException e) {
                sigParams = null;
                // Not all Signatures support AlgorithmParameters...
                if (debug != null) {
                    debug.text(Debug.TYPE_PUBLIC, className, "verify",
                            "Signature does not support AlgorithmParameters");
                }
            }

            SignatureUtil.initVerifyWithParam(sig, key,
                    SignatureUtil.getParamSpec(sigAlg.getName(), sigParams));

            byte[] info = this.getEncodedInfo();

            // DEBUG BEGIN
            /***
            HexDumpEncoder h = new HexDumpEncoder();
            System.out.println("CertificateRequest.verify() info=\r\n"
                + h.encode(info));
            ***/
            // DEBUG END

            sig.update(info);

            if (!sig.verify(signature)) {
                if (debug != null) {
                    debug.text(Debug.TYPE_PUBLIC, className, "verify",
                            "Invalid PKCS #10 signature");
                }
                throw new SignatureException("Invalid PKCS #10 signature");
            }

        } catch (InvalidKeyException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "verify", e);
            }
            throw new SignatureException("Invalid key");
        } catch (ProviderException e) {
            throw new SignatureException("Error parsing signature parameters", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SignatureException("Invalid signature parameters", e);
        }

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "verify");
        }
    }

    /**
     * Determines if this CertificationRequest object is equivalent to the
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
        if (this == other) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.TRUE);
            }
            return (true);
        }
        if (!(other instanceof CertificationRequest)) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.FALSE);
            }
            return (false);
        }

        DerValue thisDer, otherDer;
        try {
            DerOutputStream thisOut = new DerOutputStream();
            DerOutputStream otherOut = new DerOutputStream();
            this.encode(thisOut);
            thisDer = new DerValue(thisOut.toByteArray());
            ((CertificationRequest) other).encode(otherOut);
            otherDer = new DerValue(otherOut.toByteArray());
        } catch (Exception e) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "equals", "exception " + e.toString());
            }
            return (false);
        }

        if (!thisDer.equals(otherDer)) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.FALSE);
            }
            return (false);
        }

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "equals", Boolean.TRUE);
        }
        return (true);
    }

    /**
     * Returns a hashcode value for this certificate request from its
     * encoded form.
     *
     * @return the hashcode value.
     */

    public int hashCode() {
        int retval = 0;
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "hashCode");
        }
        if (signature != null)
            for (int i = 1; i < signature.length; i++)
                retval += signature[i] * i;
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "hashCode", Integer.valueOf(retval));
        }
        return (retval);
    }

    /**
     * Creates a clone of this CertificationRequest object.
     *
     * @return clone of this CertificationRequest object.
     */

    public Object clone() {

        // Can't encode an unsigned request, so use certReqInfo constructor.
        if ((this.sigAlg == null) || (this.signature == null)) {
            return (Object) new CertificationRequest(this.certReqInfo, super.provider);
        }

        try {
            DerOutputStream derout = new DerOutputStream();
            this.encode(derout);
            return (Object) new CertificationRequest(derout.toByteArray());
        } catch (Exception e) {
            // DEBUG BEGIN
            //e.printStackTrace();
            // DEBUG END
            return (Object) null;
        }
    }

    /**
     * Returns a reference to the certification request information. This
     * consists of a version number, the subject's distinguished name, the
     * subject's public key information and attributes.  The certification
     * request information is an immutable object.
     *
     * @return the certification request information for this object.
     */

    public CertificationRequestInfo getCertRequestInfo() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getCertRequestInfo");
            debug.exit(Debug.TYPE_PUBLIC, className, "getCertRequestInfo", this.certReqInfo);
        }
        return (this.certReqInfo);
    }

    /**
     * Returns a copy of the request signing algorithm identifier.
     *
     * @return the request signing algorithm for this object.
     */

    public AlgorithmId getSignatureAlgorithm() {

        AlgorithmId algID = null;
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSignatureAlgorithm");
        }
        algID = new AlgorithmId(this.sigAlg.getOID());
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getSignatureAlgorithm", algID);
        }
        return (algID);
    }

    /**
     * Returns a copy of the request signature.  The signature is constructed
     * by DER encoding the certification request info into an octet string and
     * then signing the encoded information using the signature algorithm and
     * subject's private key.
     *
     * @return the signed certification request information.
     */

    public byte[] getSignature() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getSignature");
        }
        if (this.signature == null) {
            if (debug != null) {
                debug.exit(Debug.TYPE_PUBLIC, className, "getSignature", null);
            }
            return (null);
        }

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "getSignature", this.signature.clone());
        }
        return this.signature.clone();
    }

    /**
     * Prints an E-Mailable version of the certificate request on the print
     * stream passed.  The format is a common base64 encoded one, supported
     * by most Certificate Authorities because Netscape web servers have
     * used this for some time.  Some certificate authorities expect some
     * more information, in particular contact information for the web
     * server administrator.
     *
     * @param out the print stream where the certificate request
     *    will be printed.
     *
     * @exception IOException when an output operation failed
     * @exception SignatureException when the certificate request was
     *    not yet signed.
     */

    public void print(PrintStream out) throws IOException, SignatureException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "print", out);
        }
        if (signature == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "print",
                        "CertificationRequest was not signed.");
            }
            throw new SignatureException("CertificationRequest was not signed.");
        }

        byte[] encoding = this.encode();

        try {
            out.write((CertificationRequest.BEGIN_REQUEST + "\r\n").getBytes("8859_1"));
        } catch (Exception e) {
            out.write((CertificationRequest.BEGIN_REQUEST + "\r\n").getBytes());
        }

        // The request should include the entire encoding, not solely the signature.
        byte[] encodedBytes = Base64.getEncoder().encode(encoding);
        out.write(encodedBytes);

        try {
            out.write(CertificationRequest.END_REQUEST.getBytes("8859_1"));
        } catch (Exception e) {
            out.write(CertificationRequest.END_REQUEST.getBytes());
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "print");
        }
    }

    /**
     * Provides a short description of this request.
     *
     * @return a String representation of this object.
     */

    public String toString() {

        String pubKey = null;

        try {
            pubKey = certReqInfo.getSubjectPublicKeyInfo().toString();
        } catch (Exception e) {
            pubKey = "<UNAVAILABLE>";
        }

        String sig = null;

        if (signature != null) {
            HexDumpEncoder hd = new HexDumpEncoder();
            sig = hd.encodeBuffer(signature);
        }

        PKCS9Attributes attributeSet = certReqInfo.getAttributes();

        return ("[PKCS #10 certification request:\r\n" + "\tsubject: <"
                + certReqInfo.getSubjectName() + ">" + "\r\n" + "\tpublic key info: " + pubKey
                + "\r\n" + "\tattributes: " + attributeSet.toString() + "\r\n" + "\talgorithm id: "
                + sigAlg + "\r\n" + "\tsignature:\r\n" + sig + "\r\n]");
    }

    /**
     * DER-encode the object and write the encoded bytes to the output file
     * in BASE64 format.  File will begin with the following header:
     *
     * <xmp>
     * -----BEGIN NEW CERTIFICATE REQUEST-----
     * </xmp>
     *
     * contain the BASE64 DER-encoded CertificationRequest
     * and end with the following footer:
     *
     * <xmp>
     * -----END NEW CERTIFICATE REQUEST-----
     * </xmp>
     *
     * @param filename the file to write the BASE64 DER-encoded object to.
     *
     * @exception IOException if the file cannot be created or written to.
     */

    public void writeBASE64(String filename) throws IOException {
        FileOutputStream fos = new FileOutputStream(filename);
        PrintStream ps = new PrintStream(fos);
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "writeBASE64", filename);
        }
        try {
            this.print(ps);
            ps.close();
            // ps.close() will also call fos.close()
            //fos.close();
        } catch (Exception e) {
            ps.close();
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "writeBASE64");
        }
    }

    //
    // Non-public methods
    //

    /**
     * Initializes a CertificationRequest object from a DerValue.  The DER
     * encoding must be in the format specified by the CertificationRequest
     * ASN.1 notation.  The signature should be verified before using this
     * object.
     *
     * @param encoding a DER-encoded CertificationRequest object.
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
                        "CertificationRequest parsing error");
            }
            throw new IOException("CertificationRequest parsing error");
        }

        DerInputStream in;
        DerValue[] seq;

        //
        // Outer sequence:  request info, signature algorithm, signature
        //
        in = new DerInputStream(encoding.toByteArray());
        seq = in.getSequence(3);

        if (seq.length != 3) {
            if (debug != null) {
                debug.text(Debug.TYPE_PUBLIC, className, "decode",
                        "CertificationRequest length error");
            }
            throw new IOException("CertificationRequest parsing error");
        }

        // get the certification request info
        byte[] data = seq[0].toByteArray();
        this.certReqInfo = new CertificationRequestInfo(data, super.provider);

        // get the signature algorithm id
        this.sigAlg = AlgorithmId.parse(seq[1]);

        // get the signature
        this.signature = seq[2].getBitString();
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "decode");
        }
    }

    /*
     * Return the DER-encoded certification request info.
     */

    private byte[] getEncodedInfo() throws IOException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PRIVATE, className, "getEncodedInfo");
        }
        DerOutputStream derout = new DerOutputStream();
        this.certReqInfo.encode(derout);
        if (debug != null) {
            debug.exit(Debug.TYPE_PRIVATE, className, "getEncodedInfo");
        }
        return (derout.toByteArray());
    }

    /**
     * Creates a signature for this certificate request.  This will later be
     * retrieved in either string or binary format.
     *
     * @param digest the digest used in the signing operation.  Valid
     * values are MD2, MD5 and SHA when using RSA private keys, or SHA when
     * using DSA private keys.
     * @param key the private key used to sign the certification request
     * information.
     *
     * @exception PKCSException on signing errors.
     */

    private void signThis(String digest, PrivateKey key) throws PKCSException, SignatureException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PRIVATE, className, "signThis", digest, key);
        }
        if (digest == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PRIVATE, className, "signThis", "digest must be specified.");
            }
            throw new IllegalArgumentException("digest must be specified.");
        }
        if (key == null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PRIVATE, className, "signThis", "key must be specified.");
            }
            throw new IllegalArgumentException("key must be specified.");
        }
        if (signature != null) {
            if (debug != null) {
                debug.text(Debug.TYPE_PRIVATE, className, "signThis", "Request is already signed.");
            }
            throw new SignatureException("Request is already signed.");
        }

        try {
            // Create the signature algorithm, if not already constructed.

            String sigalg = null;

            int index = digest.toUpperCase(Locale.US).indexOf("WITH");

            if (index == -1) {
                String alg = key.getAlgorithm();
                if (isRSAPSS(alg)) {
                    sigalg = "RSASSA-PSS";
                } else {
                    if (alg.equals("EC")) { // if the key type is "EC" (returned by getAlgorithm() for the "elliptic curve" key classes)
                        alg = "ECDSA"; // then use "ECDSA" for the alg string
                    }
                    sigalg = digest + "with" + alg;
                }
            } else {
                sigalg = digest;
            }

            // Create the Signature object.

            Signature sig;
            AlgorithmParameters sigParams = null;

            if (super.provider != null) {
                sig = Signature.getInstance(sigalg, super.provider);
            } else {
                sig = Signature.getInstance(sigalg);
            }

            this.sigAlg = AlgorithmId.get(sig.getAlgorithm());

            try {
                sigParams = sig.getParameters();
            } catch (UnsupportedOperationException e) {
                sigParams = null;
                // Not all Signatures support AlgorithmParameters...
                if (debug != null) {
                    debug.text(Debug.TYPE_PUBLIC, className, "signThis",
                            "Signature does not support AlgorithmParameters");
                }
            }

            SignatureUtil.initSignWithParam(sig, key,
                    SignatureUtil.getParamSpec(sigAlg.getName(), sigParams), null);

            // encode the certification request info
            DerOutputStream derout = new DerOutputStream();
            this.certReqInfo.encode(derout);
            byte[] info = derout.toByteArray();

            // DEBUG BEGIN
            /**************
            HexDumpEncoder h = new HexDumpEncoder();
            System.out.println("### CertificationRequest.signThis() key =\r\n"
                + h.encode(key.getEncoded()));
            System.out.println("### CertificationRequest.signThis() presign =\r\n"
                + h.encode(info));
            ***************/
            // DEBUG END

            // and now sign it
            //sig.update(info, 0, info.length);
            sig.update(info);
            this.signature = sig.sign();

            // DEBUG BEGIN
            //System.out.println("### CertificationRequest.signThis() signature =\r\n"
            //    + h.encode(this.signature));
            // DEBUG END

        } catch (ProviderException e) {
            e.printStackTrace();
            throw new SignatureException("Error parsing signature parameters", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new SignatureException("Invalid signature parameters", e);
        } catch (Exception e) {
            // DEBUG BEGIN
            //e.printStackTrace();
            // DEBUG END
            if (debug != null) {
                debug.exception(Debug.TYPE_PRIVATE, className, "signThis", e);
            }

            throw new PKCSException(e, "Error signing CertificateRequestInfo: " + e.toString());
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PRIVATE, className, "signThis");
        }
    }

    /**
     * Read the BASE64 encoding of a DER-encode object from the input file
     * and decode the contents into the current object.
     * This method expects the file to be in the following format, beginning with:
     *
     * <xmp>
     * -----BEGIN NEW CERTIFICATE REQUEST-----
     * </xmp>
     *
     * containing the BASE64 DER-encoded CertificationRequest
     * and ending with the following footer:
     *
     * <xmp>
     * -----END NEW CERTIFICATE REQUEST-----
     * </xmp>
     *
     * <p>
     * If the file does not contain the header and footer, this method will
     * attempt to decode the entire file.
     *
     * @param filename the BASE64 file to read an object's DER encoding from.
     *
     * @exception IOException if the file cannot be created or read from.
     */
    // Protected because parent method is protected and this can't be more
    // restrictive.
    protected void readBASE64(String filename) throws IOException {

        FileInputStream fis;
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "readBASE64", filename);
        }
        try {
            fis = new FileInputStream(filename);
        } catch (FileNotFoundException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "readBASE64", e);
            }
            throw new IOException("File " + filename + " not found.");
        }
        int numBytes = fis.available();
        byte[] contents = new byte[numBytes];
        fis.read(contents);
        fis.close();

        String crlf = "\r\n";
        byte[] crlfbytes = null;
        String pszcontents = null;
        try {
            crlfbytes = crlf.getBytes("8859_1");
            pszcontents = new String(contents, "8859_1");
        } catch (UnsupportedEncodingException e) {
            crlfbytes = crlf.getBytes();
            pszcontents = new String(contents);
        }

        StringReader sreader = new StringReader(pszcontents);
        BufferedReader breader = new BufferedReader(sreader);
        String inline = null;
        boolean bbody = false;
        boolean bfooter = false;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ByteArrayOutputStream bos2 = new ByteArrayOutputStream();

        while ((inline = breader.readLine()) != null) {
            // Store the contents in an alterative stream in case we don't find
            // any headers.
            try {
                bos2.write(inline.getBytes("8859_1"));
            } catch (UnsupportedEncodingException e) {
                bos2.write(inline.getBytes());
            }

            if (inline.equals(CertificationRequest.BEGIN_REQUEST)) {
                bbody = true;
                continue;
            }
            if (inline.equals(CertificationRequest.END_REQUEST)) {
                bfooter = true;
                break;
            }
            if (bbody) {
                try {
                    bos.write(inline.getBytes("8859_1"));
                } catch (UnsupportedEncodingException e) {
                    bos.write(inline.getBytes());
                }
                bos.write(crlfbytes);
            }
        }

        ByteArrayInputStream bais = null;

        if (!bbody && !bfooter) {
            bais = new ByteArrayInputStream(bos2.toByteArray());
        } else {
            if (!bbody) {
                if (debug != null) {
                    debug.text(Debug.TYPE_PUBLIC, className, "readBASE64",
                            "File did not include the following header: "
                                    + CertificationRequest.BEGIN_REQUEST);
                }
                throw new IOException("File did not include the following header: "
                        + CertificationRequest.BEGIN_REQUEST);
            }
            if (!bfooter) {
                if (debug != null) {
                    debug.text(Debug.TYPE_PUBLIC, className, "readBASE64",
                            "File did not include the following footer: "
                                    + CertificationRequest.END_REQUEST);
                }
                throw new IOException("File did not include the following footer: "
                        + CertificationRequest.END_REQUEST);
            }

            bais = new ByteArrayInputStream(bos.toByteArray());
        }

        byte[] encoding = Base64.getDecoder().decode(bais.readAllBytes());

        decode(encoding);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "readBASE64");
        }
    }

    public static boolean isRSAPSS(String name) {

        final String[] RSAPSS_ALIASES = {"RSASSA-PSS", "RSAPSS", "RSA-PSS", "RSASA-PSS",
                "1.2.840.113549.1.1.10", "OID.1.2.840.113549.1.1.10"};

        if (name == null || name.length() <= 0) {
            return false;
        }
        for (String s : RSAPSS_ALIASES) {
            if (name.equalsIgnoreCase(s)) {
                return true;
            }
        }
        return false;
    }

}
