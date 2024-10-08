/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base.certificateutils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Base64;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;

/**
 * Abstract class inherited by other PKCS objects.
 */

public abstract class PKCSDerObject implements Cloneable {

    protected String provider = null;
    private static Debug debug = Debug.getInstance("jceplus");
    private static String className = "com.ibm.security.pkcsutil.PKCSDerObject";

    //
    // Constructors
    //

    /**
     * Create a PKCSDerObject subclass with attributes to be filled in at a
     * later stage.
     */
    // This ctor is required by subclasses that have default constructors
    // (eg, SignerInfo).
    public PKCSDerObject() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "PKCSDerObject");
            debug.exit(Debug.TYPE_PUBLIC, className, "PKCSDerObject");
        }
    }

    /**
     * Create a PKCSDerObject subclass with attributes to be filled in at a
     * later stage.
     */
    // This ctor is required by subclasses that have default constructors
    // (eg, SignerInfo).
    public PKCSDerObject(String provider) {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "PKCSDerObject", provider);
        }
        if (provider != null) {
            this.provider = new String(provider);
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "PKCSDerObject");
        }
    }

    /**
     * Create a PKCSDerObject subclass with a DER-encoded byte array.
     */

    // If you have a DerValue object, convert it to a byte array using its
    // toByteArray() method and use the byte array in this constructor.

    public PKCSDerObject(byte[] der) throws IOException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "PKCSDerObject", der);
        }
        decode(der);

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "PKCSDerObject");
        }
    }

    /**
     * Create a PKCSDerObject subclass with a DER-encoded byte array.
     */

    // If you have a DerValue object, convert it to a byte array using its
    // toByteArray() method and use the byte array in this constructor.

    public PKCSDerObject(byte[] der, String provider) throws IOException {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "PKCSDerObject", der, provider);
        }
        if (provider != null) {
            this.provider = new String(provider);
        }
        decode(der);

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "PKCSDerObject");
        }
    }

    /**
     * Create a PKCSDerObject subclass with the filename of the DER-encoded
     * or BASE64-encoded object.
     *
     * @param filename name of the DER-encoded or base64-encoded object
     * @param base64 true if BASE64-encoded, false if DER-encoded
     *
     * @exception IOException on decoding errors.
     */
    public PKCSDerObject(String filename, boolean base64) throws IOException {
        if (debug != null) {
            Object[] parms = {filename, base64};
            debug.entry(Debug.TYPE_PUBLIC, className, "PKCSDerObject", parms);
        }
        if (base64) {
            this.readBASE64(filename);
        } else {
            this.read(filename);
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "PKCSDerObject");
        }
    }

    /**
     * Create a PKCSDerObject subclass with the filename of the DER-encoded
     * or BASE64-encoded object.
     *
     * @param filename name of the DER-encoded or base64-encoded object
     * @param base64 true if BASE64-encoded, false if DER-encoded
     * @param provider the provider to be used
     *
     * @exception IOException on decoding errors.
     */
    public PKCSDerObject(String filename, boolean base64, String provider) throws IOException {
        if (debug != null) {
            Object[] parms = {filename, base64, provider};
            debug.entry(Debug.TYPE_PUBLIC, className, "PKCSDerObject", parms);
        }
        if (provider != null) {
            this.provider = new String(provider);
        }
        if (base64) {
            this.readBASE64(filename);
        } else {
            this.read(filename);
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "PKCSDerObject");
        }
    }

    //
    // Public methods
    //

    /**
     * Return an encoded DER byte array.
     */
    public byte[] encode() throws IOException {

        DerOutputStream out = new DerOutputStream();
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "encode");
        }
        encode(out);

        byte[] retval = out.toByteArray();
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "encode", retval);
        }
        return retval;
    }

    /**
     * Returns a hashcode value for this object.
     */
    public int hashCode() {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "hashCode");
            debug.exit(Debug.TYPE_PUBLIC, className, "hashCode", toString().hashCode());
        }
        return toString().hashCode();
    }

    /**
     * Return the ObjectIdentifier for the object, if specified.
     */
    public ObjectIdentifier getObjectIdentifier() {
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "getObjectIdentifier");
            debug.exit(Debug.TYPE_PUBLIC, className, "getObjectIdentifier", null);
        }
        return null;
    }

    /**
     * DER-encode the object and write the encoded bytes to the output file.
     * If the isBase64 boolean argument is true, write the DER-encoded object
     * in BASE64 format.
     *
     * @param filename the file to write the DER-encoded object to.
     * @param isBase64 true if the DER-encoded object should be written in
     * BASE64 format, false otherwise.
     *
     * @exception IOException if the file cannot be created or written to.
     */
    public void write(String filename, boolean isBase64) throws IOException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "write", filename, isBase64);
        }
        if (isBase64) {
            writeBASE64(filename);
        } else {
            write(filename);
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "write");
        }
    }

    //
    // Non-public methods
    //

    /**
     * Decode the attributes of the PKCSDerObject subclass from a DER byte
     * array.
     */
    // Keep protected as it is needed by subclasses (eg, PKCS9DerObject).
    protected void decode(byte[] der) throws IOException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "decode", der);
        }
        try {
            DerInputStream derin = new DerInputStream(der);
            DerValue encoding = derin.getDerValue();
            decode(encoding);
        } catch (IOException ex) {
            if (debug != null) {
                System.out.println("The exception shown within the trace data below was thrown \n"
                        + "by PKCSDerObject.decode(byte[] der) while trying to decode \n"
                        + "an object that it assumed was in raw der encoded form. Either, \n"
                        + "there is an error within that raw der encoded data which \n"
                        + "led to this exception, or the data itself was actually base64 \n"
                        + "encoded. PKCSDerObject.decode(byte[] der) will now re-attempt \n"
                        + "the decoding operation. This time, however, it will assume \n"
                        + "that the data is also base64 encoded, and will attempt to \n"
                        + "remove the base64 encoding before trying to decode the der \n"
                        + "encoded object. If a second exception is thrown, then there \n"
                        + "is likely either a der encoding problem with the object being \n"
                        + "decoded (most likely) or there is a problem with the base64 \n"
                        + "encoding (less likely).");
                ex.printStackTrace();
            }

            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(der);
                Base64.Decoder decoder = Base64.getDecoder();
                //byte[] encodingData = decoder.decodeBuffer(bis);
                decoder.wrap(bis);
                byte[] encodingData = bis.readAllBytes();
                DerInputStream derin = new DerInputStream(encodingData);
                DerValue encoding = derin.getDerValue();
                decode(encoding);
            } catch (Exception ex1) {
                throw ex; // If the data is not BASE64 encoded, then just throw the original exception.
                          // It will be the most meaningful to the caller.
            }
        }
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "decode");
        }
    }

    /**
     * Read the byte array of a DER-encode object from the input file
     * and decode the contents into the current object.
     *
     * @param filename the file to read an object's DER encoding from.
     *
     * @exception IOException if the file cannot be created or read from.
     */

    // Keep protected as it may be needed by pkcs7 classes.
    // Needs to be protected, not private, so that subclass constructors
    // may call the method if they override it.

    protected void read(String filename) throws IOException {

        FileInputStream fis;
        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "read", filename);
        }
        try {
            fis = new FileInputStream(filename);
        } catch (FileNotFoundException e) {
            if (debug != null) {
                debug.exception(Debug.TYPE_PUBLIC, className, "read", e);
            }
            throw new IOException("File " + filename + " not found.");
        }
        int numBytes = fis.available();
        byte[] encoding = new byte[numBytes];
        fis.read(encoding);
        fis.close();

        decode(encoding);
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "read");
        }
    }

    /**
     * Read the BASE64 encoding of a DER-encode object from the input file
     * and decode the contents into the current object.
     *
     * @param filename the BASE64 file to read an object's DER encoding from.
     *
     * @exception IOException if the file cannot be created or read from.
     */

    // Keep protected as it is needed by ContentInfo.
    // Needs to be protected, not private, so that subclass constructors
    // may call the method if they override it.

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

        Base64.Decoder decoder = Base64.getDecoder();
        //byte[] encoding = decoder.decodeBuffer(fis);
        decoder.wrap(fis);
        byte[] encoding = fis.readAllBytes();
        fis.close();

        decode(encoding);

        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "readBASE64");
        }
    }

    /**
     * DER-encode the object and write the encoded bytes to the output file.
     *
     * @param filename the file to write the DER-encoded object to.
     *
     * @exception IOException if the file cannot be created or written to.
     */

    // Needs to be protected, not private, so that subclass constructors
    // may call the method if they override it.

    protected void write(String filename) throws IOException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "write", filename);
        }
        FileOutputStream fos = new FileOutputStream(filename);
        this.encode(fos);
        fos.close();
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "write");
        }
    }

    /**
     * DER-encode the object and write the encoded bytes to the output file
     * in BASE64 format.
     *
     * @param filename the file to write the BASE64 DER-encoded object to.
     *
     * @exception IOException if the file cannot be created or written to.
     */

    // Needs to be protected, not private, so that subclass constructors
    // may call the method if they override it.

    protected void writeBASE64(String filename) throws IOException {

        if (debug != null) {
            debug.entry(Debug.TYPE_PUBLIC, className, "writeBASE64", filename);
        }
        FileOutputStream fos = new FileOutputStream(filename);
        DerOutputStream derout = new DerOutputStream();
        this.encode(derout);
        byte[] encoding = derout.toByteArray();
        Base64.Encoder encoder = Base64.getEncoder();
        encoder.wrap(fos);
        fos.write(encoding);
        //encoder.encode(encoding,fos);

        fos.close();
        if (debug != null) {
            debug.exit(Debug.TYPE_PUBLIC, className, "writeBASE64");
        }
    }

    //
    // Abstract methods
    //

    /**
     * Decode the attributes of the PKCSDerObject subclass from a DerValue.
     */
    protected abstract void decode(DerValue encoding) throws IOException;

    /**
     * Return an encoded DER byte array on an OutputStream.
     */
    public abstract void encode(OutputStream os) throws IOException;

    /**
    * Returns a string representation of this object.
    */
    public abstract String toString();

    /**
     * Determines if this object is equivalent to the input object.
     *
     * @param other the object to compare this one to.
     *
     * @return true, if the two objects are equivalent, false otherwise.
     */
    public abstract boolean equals(Object obj);
}
